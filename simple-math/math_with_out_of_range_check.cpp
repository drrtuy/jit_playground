#include <llvm-16/llvm/IR/BasicBlock.h>
#include <llvm-16/llvm/IR/Function.h>
#include <llvm-16/llvm/IR/IRBuilder.h>
#include <llvm-16/llvm/IR/LLVMContext.h>
#include <llvm-16/llvm/IR/LegacyPassManager.h>
#include <llvm-16/llvm/IR/Module.h>
#include <llvm-16/llvm/IR/Verifier.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/MC/SubtargetFeature.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/DynamicLibrary.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/TargetParser/Host.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

#include <iostream>
#include <memory>
#include <optional>
#include <sstream>

using namespace llvm;

std::unique_ptr<llvm::TargetMachine> getTargetMachine() {
  static std::once_flag llvm_target_machine_initialized;
  std::call_once(llvm_target_machine_initialized, []() {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
  });
  std::string error;
  auto cpu = llvm::sys::getHostCPUName();
  auto triple = llvm::sys::getProcessTriple();
  const auto *target = llvm::TargetRegistry::lookupTarget(triple, error);
  if (!target) {
    throw std::logic_error("Failed to lookup target: " + error);
  }
  llvm::SubtargetFeatures features;
  llvm::StringMap<bool> feature_map;
  if (llvm::sys::getHostCPUFeatures(feature_map))
    for (auto &f : feature_map)
      features.AddFeature(f.first(), f.second);

  llvm::TargetOptions options;

  bool jit = true;
  auto *target_machine = target->createTargetMachine(
      triple, cpu, features.getString(), options, std::nullopt, std::nullopt,
      llvm::CodeGenOpt::Aggressive, jit);

  if (!target_machine)
    throw std::logic_error("Failed to create target machine");

  return std::unique_ptr<llvm::TargetMachine>(target_machine);
}

LLVMContext Context;
IRBuilder<> b(Context);

inline llvm::Value *compileInt_(llvm::IRBuilder<> &b, llvm::Value *l,
                                llvm::Value *r, const std::string &fOp) {
  if (fOp == "add")
    return b.CreateAdd(l, r);

  if (fOp == "sub")
    return b.CreateSub(l, r);

  if (fOp == "mul")
    return b.CreateMul(l, r);

  if (fOp == "div") {
    if (l->getType()->isIntegerTy())
      throw std::logic_error(
          "ArithmeticOperator::compile(): Div not support int");
    else {
      // WIP check if this handles zero div case.
      return b.CreateFDiv(l, r);
    }
  }
  std::ostringstream oss;
  oss << "invalid arithmetic operation: " << fOp;
  throw std::logic_error(oss.str());
}

template <int len>
static llvm::Value *compileIntField(llvm::IRBuilder<> &b,
                                    llvm::Value *dataValue, uint32_t offset,
                                    bool isInt64 = true) {
  auto *dataPtr =
      b.CreateConstInBoundsGEP1_64(b.getInt8Ty(), dataValue, offset);
  llvm::Value *result;
  switch (len) {
  case 1:
    result = b.CreateLoad(b.getInt8Ty(), dataPtr);
    break;
  case 2:
    result =
        b.CreateLoad(b.getInt16Ty(),
                     b.CreateBitCast(dataPtr, b.getInt16Ty()->getPointerTo()));
    break;
  case 4:
    result =
        b.CreateLoad(b.getInt32Ty(),
                     b.CreateBitCast(dataPtr, b.getInt32Ty()->getPointerTo()));
    break;
  case 8:
    result =
        b.CreateLoad(b.getInt64Ty(),
                     b.CreateBitCast(dataPtr, b.getInt64Ty()->getPointerTo()));
    break;
  default:
    throw std::logic_error("Row::compileIntField(): bad length.");
  }
  return isInt64 ? b.CreateSExt(result, b.getInt64Ty()) : result;
}

llvm::Value *compileIntWithConditions_(llvm::IRBuilder<> &b, llvm::Value *l,
                                       llvm::Value *r, llvm::Value *isNull,
                                       llvm::Value *dataConditionError) {
  bool signedLeft = true;
  bool signedRight = true;

  // TODO use template to decide the number of bits of the type.
  auto *intBigerType = llvm::IntegerType::get(b.getContext(), 128);
  auto *intCurrentType = llvm::IntegerType::get(b.getContext(), 64);

  // auto *lCasted = (signedLeft) ? b.CreateSExt(l, intBigerType, "l_to_int128")
  //                              : b.CreateZExt(l, intBigerType,
  //                              "l_to_int128");
  // auto *rCasted = (signedRight) ? b.CreateSExt(r, intBigerType,
  // "r_to_int128")
  //                               : b.CreateZExt(r, intBigerType,
  //                               "r_to_int128");
  // auto *operReturn = compileInt_(b, lCasted, rCasted, "add");
  auto *lVal = compileIntField<8>(b, l, 0);
  auto *rVal = compileIntField<8>(b, r, 0);
  auto *operReturn = compileInt_(b, lVal, rVal, "add");
  return operReturn;

  // auto minValue = 0ULL;                    // Cast ?
  // auto maxValue = 18446744073709551613ULL; // Cast ?
  // auto *cmpGTMax = b.CreateICmpSGT(
  //     operReturn, llvm::ConstantInt::get(operReturn->getType(), maxValue));
  // auto *cmpLTMin = b.CreateICmpSLT(
  //     operReturn, llvm::ConstantInt::get(operReturn->getType(), minValue));
  // auto *cmpOutOfRange = b.CreateOr(cmpGTMax, cmpLTMin);

  // auto *ifOutOfRangeBlock = llvm::BasicBlock::Create(
  //     b.getContext(), "ifOutOfRange", b.GetInsertBlock()->getParent());
  // auto* elseNoopBlock = llvm::BasicBlock::Create(b.getContext(), "elseNoop",
  // b.GetInsertBlock()->getParent());
  // [[maybe_unused]] auto *mergeBlock = llvm::BasicBlock::Create(
  //     b.getContext(), "merge", b.GetInsertBlock()->getParent());
  // [[maybe_unused]] auto *ifOutOfRangeElseBlocks =
  //     b.CreateCondBr(cmpOutOfRange, ifOutOfRangeBlock, mergeBlock);

  // b.SetInsertPoint(ifOutOfRangeBlock);
  // auto *getDataConditionError =
  //     b.CreateLoad(b.getInt32Ty(), dataConditionError);
  // auto *setOutOfRangeBitInDataCondition =
  //     b.CreateOr(getDataConditionError, b.getInt32(131072));
  // [[maybe_unused]] auto *storeIsOutOfRange =
  //     b.CreateStore(setOutOfRangeBitInDataCondition, dataConditionError);

  // b.SetInsertPoint(mergeBlock);
  // auto *res = b.CreateTrunc(operReturn, intCurrentType,
  // "truncatedToSmaller");

  // return res;
}

void runOptimizationPassesOnModule(llvm::Module &module) {
  llvm::PassManagerBuilder pass_manager_builder;
  llvm::legacy::PassManager mpm;
  llvm::legacy::FunctionPassManager fpm(&module);

  pass_manager_builder.OptLevel = 2;
  pass_manager_builder.SLPVectorize = true;
  pass_manager_builder.LoopVectorize = true;
  pass_manager_builder.VerifyInput = true;
  pass_manager_builder.VerifyOutput = true;
#if LLVM_VERSION_MAJOR < 16
  pass_manager_builder.RerollLoops = true;
  target_machine->adjustPassManager(pass_manager_builder);
#endif

  fpm.add(llvm::createTargetTransformInfoWrapperPass(
      getTargetMachine()->getTargetIRAnalysis()));
  mpm.add(llvm::createTargetTransformInfoWrapperPass(
      getTargetMachine()->getTargetIRAnalysis()));

  pass_manager_builder.populateFunctionPassManager(fpm);
  pass_manager_builder.populateModulePassManager(mpm);

  fpm.doInitialization();
  std::cout << "JIT::runOptimizationPassesOnModule 1" << std::endl;
  module.print(llvm::outs(), nullptr);

  for (auto &function : module) {
    fpm.run(function);
  }

  std::cout << "JIT::runOptimizationPassesOnModule 2" << std::endl;
  module.print(llvm::outs(), nullptr);
  fpm.doFinalization();
  std::cout << "JIT::runOptimizationPassesOnModule 3" << std::endl;
  module.print(llvm::outs(), nullptr);

  // // WIP the module opt pass removes the function compiled
  // Module opt passes aggresivelly remove "unreferenced" functions from
  // a module.
  // mpm.run(module);

  std::cout << "JIT::runOptimizationPassesOnModule 4" << std::endl;
  module.print(llvm::outs(), nullptr);
}

int main() {
  // Create an empty module and a function within it
  auto module = std::make_unique<Module>("module", Context);

  auto *returnType = b.getInt64Ty();
  auto *dataType = b.getInt8Ty()->getPointerTo();
  auto *isNullType = b.getInt1Ty()->getPointerTo();
  auto *dataConditionErrorType = b.getInt8Ty()->getPointerTo();

  auto expressionName = std::string("some");
  auto *funcType = llvm::FunctionType::get(
      returnType, {dataType, dataType, isNullType, dataConditionErrorType},
      false);
  auto *func = llvm::Function::Create(funcType, llvm::Function::ExternalLinkage,
                                      expressionName, *module);
  func->setDoesNotThrow();
  auto *args = func->args().begin();
  llvm::Value *l = args++;
  llvm::Value *r = args++;
  llvm::Value *isNullPtr = args++;
  llvm::Value *dataConditionPtr = args++;

  auto *entry = llvm::BasicBlock::Create(b.getContext(), "entry", func);
  b.SetInsertPoint(entry);

  auto *ret = compileIntWithConditions_(b, l, r, isNullPtr, dataConditionPtr);
  b.CreateRet(ret);

  // Verify the function
  verifyFunction(*func);
  module->print(outs(), nullptr);

  runOptimizationPassesOnModule(*module);

  // Print out the module
  module->print(outs(), nullptr);

  return 0;
}
