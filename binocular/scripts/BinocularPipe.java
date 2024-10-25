/*
 Initialize all resources needed
 Open up a named pipe specified by the parameters it gets called with
 Wait for input and handle it
    essentially an rpc implementation of disassembler.py
 */

//Makes functions out of a run of selected ARM or Thumb function pointers 
//@category BINocular

import java.util.LinkedList;
import java.util.List;
import java.util.HashMap;
import java.util.HashSet;
import java.nio.file.Paths;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import ghidra.app.script.GhidraScript;

import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.Endian;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceType;
import ghidra.program.model.block.BasicBlockModel;

class BINVariable{
    public String type;
    public String name;
    public boolean isRegister;
    public boolean isStack;
    public int stackOffset;

    public BINVariable(String type, String name, boolean isRegister, boolean isStack){
        this.type = type;
        this.name = name;
        this.isRegister = isRegister;
        this.isStack = isStack;
        this.stackOffset = 0;
    }

    public byte[] getBytes(){
        int lengths = this.type.length() + this.name.length() + 2;

        ByteBuffer buf = ByteBuffer.allocate(lengths + 6);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.put(this.type.getBytes());
        buf.put((byte)0);
        buf.put(this.name.getBytes());
        buf.put((byte)0);
        buf.put(this.isRegister ? (byte)1 : (byte)0);
        buf.put(this.isStack ? (byte)1 : (byte)0);
        buf.putInt(this.stackOffset);

        return buf.array();
    }
}

public class BinocularPipe extends GhidraScript{
    // Fuck enums
    final byte QUIT = 0;
    final byte TEST = 2;
    final byte BINARY_NAME = 4;
    final byte ENTRY_POINT = 6;
    final byte ARCHITECTURE = 8;
    final byte ENDIANNESS = 10;
    final byte BITNESS = 12;
    final byte BASE_ADDR = 14;
    final byte DYN_LIBS = 16;
    final byte FUNCS = 18;
    // final byte FUNC_ADDR = 20;
    final byte FUNC_NAME = 22;
    final byte FUNC_ARGS = 24;
    final byte FUNC_RETURN = 26;
    final byte FUNC_STACK_FRAME = 28;
    final byte FUNC_CALLERS = 30;
    final byte FUNC_CALLEES = 32;
    final byte FUNC_XREFS = 34;
    final byte FUNC_BB = 36;
    final byte BB_ADDR = 38;
    final byte BB_BRANCHES = 40;
    final byte BB_INSTR = 42;
    // final byte SECTIONS = 44;
    final byte DECOMP = 46;
    final byte FUNC_VARS = 48;
    final byte INSTR_PCODE = 50;
    final byte INSTR_COMMENT = 52;
    final byte STRINGS = 54;

    final byte UNKNOWN = 0;
    final byte JUMP = 1;
    final byte CALL = 2;
    final byte READ = 3;
    final byte WRITE = 4;
    final byte DATA = 5;

    SymbolTable st;
    FunctionManager fm;
    LanguageDescription ld;
    BasicBlockModel bbm;
    ReferenceManager rm;
    ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
    DecompInterface decomp = new DecompInterface();
    HashMap<Long, CodeBlock> basicBlockMap = new HashMap<>();
    HashMap<Function, DecompileResults> decompCache = new HashMap<>();
    int timeout;

    @Override
    public void run() throws Exception{
        String[] args = this.getScriptArgs();
        String rootPipePath = args[0];
        String recvPath = Paths.get(rootPipePath, "send").toString();
        String sendPath = Paths.get(rootPipePath, "recv").toString();

        this.st = currentProgram.getSymbolTable();
        this.fm = currentProgram.getFunctionManager();
        this.ld = currentProgram.getLanguage().getLanguageDescription();
        this.rm = currentProgram.getReferenceManager();
        this.bbm = new BasicBlockModel(currentProgram);
        // Gracious 5 min timeout for decompilation
        this.timeout = 60 * 5;
        decomp.openProgram(currentProgram);

        boolean running = true;
        while (running){
            int id;
            long bbAddr = 0;
            long funcAddr = 0;
            byte[] buff = new byte[8];
            byte[] response;
            int res_size = 0;

            try(BufferedInputStream rpipe = new BufferedInputStream(new FileInputStream(new File(recvPath)))){
                while(rpipe.available() == 0){
                    // Waiting for Data
                    Thread.sleep(100);
                }
                // System.out.println("Got Request!");

                // Add some sort of timeout
                id = rpipe.read();
                if (id == QUIT){
                    running = false;
                }

                rpipe.read(buff, 0, 8);
                bbAddr = ByteBuffer.wrap(buff).getLong();

                rpipe.read(buff, 0, 8);
                funcAddr = ByteBuffer.wrap(buff).getLong();
            }

            response = this.handleCommand(id, bbAddr, funcAddr);
            
            if (response == null){
                res_size = 0;
            }else{
                res_size = response.length;
            }

            try(BufferedOutputStream wpipe = new BufferedOutputStream(new FileOutputStream(new File(sendPath)))){
                ByteBuffer out_buff = ByteBuffer.allocate(res_size + 5);
                out_buff.order(ByteOrder.BIG_ENDIAN);
                out_buff.put((byte)(id+1));
                out_buff.putInt(res_size);
                if (res_size > 0)
                    out_buff.put(response);

                byte[] raw = out_buff.array();
                // for (byte b: raw){
                //     System.out.printf("%02X ", b);
                // }
                wpipe.write(raw, 0, raw.length);
                wpipe.flush();
            }

        }
    }

    private byte[] handleCommand(int id, long bbAddr, long funcAddr){
        Function f = null;
        CodeBlock bb = null;

        if (funcAddr != 0){
            Address a = this.getAddress(funcAddr);
            f = fm.getFunctionAt(a);
        }

        if (bbAddr != 0){
            Long addrWrap = bbAddr;
            bb = this.basicBlockMap.get(addrWrap);
        }

        switch(id){
            case TEST:
                return this.smokeTest().getBytes();
            case BINARY_NAME:
                return this.getBinaryName().getBytes();
            case ENTRY_POINT:
                return this.packLong(this.getEntryPoint().getOffset());
            case ARCHITECTURE:
                return this.getArchitecture().getBytes();
            case ENDIANNESS:
                return this.getEndianness().getDisplayName().getBytes();
            case BITNESS:
                return this.packInt(this.getBitness());
            case BASE_ADDR:
                return this.packLong(this.getBaseAddress().getOffset());
            case DYN_LIBS:
                return this.packStringList(this.getDynamicLibs());
            case FUNCS:
                return this.packFunctionList(this.getFunctionIterator());
            // case FUNC_ADDR:
            //     return; // No need to implement since we are using function's address as a key to all function things
            case FUNC_NAME:
                return this.getFunctionName(f).getBytes();
            case FUNC_ARGS:
                return this.packStringList(this.getFunctionArgs(f));
            case FUNC_RETURN:
                return this.getFunctionReturnType(f).getBytes();
            case FUNC_STACK_FRAME:
                return this.packInt(this.getFunctionStackFrameSize(f));
            case FUNC_CALLERS:
                return this.packFunctionList(this.getFunctionCallers(f));
            case FUNC_CALLEES:
                return this.packFunctionList(this.getFunctionCallees(f));
            case FUNC_XREFS:
                return this.packReferenceList(this.getFunctionXRefs(f));
            // case FUNC_BB:
            //     return;
            // case BB_ADDR:
            //     return;
            // case BB_BRANCHES:
            //     return;
            // case BB_INSTR:
            //     return;
            // case DECOMP:
            //     return;
            // case FUNC_VARS:
            //     return;
            // case INSTR_PCODE:
            //     return;
            // case INSTR_COMMENT:
            //     return;
            // case STRINGS:
            //     return;
            default:
                return null;
        }
    }

    private byte[] packLong(long l){
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putLong(l);
        return buf.array();
    }

    private byte[] packInt(int i){
        ByteBuffer buf = ByteBuffer.allocate(4);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putInt(i);
        return buf.array();
    }

    private byte[] packStringList(List<String> list){
        int total_length = 0;
        LinkedList<byte[]> raw_list = new LinkedList<byte[]>();
        for (String s: list){
            byte[] encoded = s.getBytes();
            raw_list.add(encoded);
            total_length += encoded.length + 1;
        }

        if (total_length == 0)
            return null;

        ByteBuffer buf = ByteBuffer.allocate(total_length);
        buf.order(ByteOrder.BIG_ENDIAN);
        for (byte[] b: raw_list){
            buf.put(b);
            buf.put((byte)0);
        }

        return buf.array();
    }

    private byte[] packFunctionList(List<Function> list){
        if (list.size() == 0)
            return null;

        ByteBuffer buf = ByteBuffer.allocate(8 * list.size());
        buf.order(ByteOrder.BIG_ENDIAN);
        for (Function f: list){
            buf.putLong(f.getEntryPoint().getOffset());
        }
        return buf.array();
    }

    private byte[] packVariableList(List<BINVariable> list){
        if (list.size() == 0)
            return null;

        // Pascal String Style (length then data)
        int total_length = 0;
        LinkedList<byte[]> raw_list = new LinkedList<byte[]>();
        for(BINVariable var: list){
            byte[] encoded = var.getBytes();
            raw_list.add(encoded);
            total_length += encoded.length + 4;
        }
        ByteBuffer buf = ByteBuffer.allocate(total_length);
        buf.order(ByteOrder.BIG_ENDIAN);
        for (byte[] b: raw_list){
            buf.putInt(b.length);
            buf.put(b);
        }

        return buf.array();
    }

    private byte[] packReferenceList(List<Reference> refs){
        int total_length = refs.size() * (1+8+8); // 1 bytes + 2 longs
        ByteBuffer buf = ByteBuffer.allocate(total_length);
        buf.order(ByteOrder.BIG_ENDIAN);
        for(Reference r: refs){
            ReferenceType rType = r.getReferenceType();
            if (rType.isCall()){
                buf.put(CALL);
            }else if (rType.isJump()){
                buf.put(JUMP);
            }else if (rType.isRead()){
                buf.put(READ);
            }else if (rType.isWrite()){
                buf.put(WRITE);
            }else{
                buf.put((byte)0);
            }

            buf.putLong(r.getToAddress().getOffset());
            buf.putLong(r.getFromAddress().getOffset());
        }
        return buf.array();
    }

    private Address getAddress(long addr){
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
    }

    public String smokeTest(){
        return "BINocular Test";
    }

    public String getBinaryName(){
        return currentProgram.getName();
    }

    public Address getEntryPoint(){
        AddressIterator aIter = st.getExternalEntryPointIterator();
        while (aIter.hasNext()){
            Address addr = aIter.next();
            Symbol sym = this.getSymbolAt(addr);
            if (sym.getSymbolType().equals(SymbolType.FUNCTION)){
                Function entry = fm.getFunctionAt(addr);
                if (entry.getCallingConventionName() == "processEntry") {
                    return addr;
                } 
            }
        }
        return null;
    }

    public String getArchitecture(){
        return ld.getProcessor().toString();
    }

    public Endian getEndianness(){
        return ld.getEndian();
    }

    public int getBitness(){
        return ld.getSize();
    }

    public Address getBaseAddress(){
        return currentProgram.getImageBase();
    }

    public List<String> getStrings(){
        LinkedList<String> list = new LinkedList<>();
        for(Data d: DefinedDataIterator.definedStrings(currentProgram)){
            list.add(d.getValue().toString());
        }
        return list;
    }

    public List<String> getDynamicLibs(){
        LinkedList<String> libs = new LinkedList<>();
        ExternalManager em = currentProgram.getExternalManager();
        for(String name: em.getExternalLibraryNames()){
            if (!name.equals("<EXTERNAL>")){
                libs.add(name);
            }
        }

        return libs;
    }

    public List<Function> getFunctionIterator(){
        LinkedList<Function> funcs = new LinkedList<>();
        for(Function f: fm.getFunctions(true)){
            funcs.add(f);
        }
        return funcs;
    }

    public String getFunctionName(Function f){
        return f.getName();
    }

    private DecompileResults decompile(Function f){
        DecompileResults res = decompCache.get(f);
        if (res != null){
            return res;
        }

        return decomp.decompileFunction(f, timeout, monitor);
    }

    public List<String> getFunctionArgs(Function f){
        LinkedList<String> args = new LinkedList<>();
        DecompileResults res = this.decompile(f);
        HighFunction high = res.getHighFunction();
        if (high == null){
            return args;
        }

        FunctionPrototype proto = high.getFunctionPrototype();

        int numParams = proto.getNumParams();
        for(int i = 0; i < numParams; i++){
            args.add(
                proto.getParam(i).getDataType().toString() +
                " " +
                proto.getParam(i).getName().toString()
            );
        }

        if (f.hasVarArgs()){
            args.add("...");
        }

        return args;
    }

    public String getFunctionReturnType(Function f){
        DecompileResults res = this.decompile(f);
        HighFunction high = res.getHighFunction();
        if (high == null){
            return null;
        }

        return high.getFunctionPrototype().getReturnType().toString();        
    }

    public int getFunctionStackFrameSize(Function f){
        return f.getStackFrame().getFrameSize();
    }

    public List<BINVariable> getFunctionVars(Function f){
        LinkedList<BINVariable> vars = new LinkedList<>();
        for(Variable v: f.getLocalVariables()){
            BINVariable var = new BINVariable(v.getDataType().getName().toString(), v.getName().toString(), v.isRegisterVariable(), v.isStackVariable());
            if (var.isStack){
                var.stackOffset = v.getStackOffset();
            }
            vars.add(var);
        }
        return vars;
    }
    
    public boolean isThunk(Function f){
        return f.isThunk();
    }

    public String getFunctionDecompilation(Function f){
        DecompileResults res = this.decompile(f);
        DecompiledFunction dFunc = res.getDecompiledFunction();
        if (dFunc == null){
            return null;
        }

        return dFunc.getC();
    }

    public List<Function> getFunctionCallees(Function f){
        LinkedList<Function> list = new LinkedList<>();
        for (Reference ref: rm.getReferencesTo(f.getEntryPoint())){
            if (ref.getReferenceType().isCall()){
                Function caller = fm.getFunctionContaining(ref.getFromAddress());
                if (caller != null){
                    list.add(caller);
                }
            }
        }
        return list;
    }

    public List<Function> getFunctionCallers(Function f){
        LinkedList<Function> list = new LinkedList<>();
        for(Address addr: f.getBody().getAddresses(true)){
            for(Reference ref: rm.getReferencesFrom(addr)){
                if (ref.getReferenceType().isCall()){
                    list.add(fm.getFunctionAt(ref.getToAddress()))
                }
            }
        }
        return list;
    }

    public List<Reference> getFunctionXRefs(Funciton f){
        LinkedList<Reference> refs = new LinkedList<>();
        for(Address addr: f.getBody().getAddresses(true)){
            for(Reference r: rm.getReferencesFrom(addr)){
                refs.add(r);
            }
            for(Reference r: rm.getReferencesTo(addr)){
                refs.add(r);
            }
        }
        return refs;
    }    
    
    public List<CodeBlock> getFunctionBasicBlocks(Function f){
        LinkedList<CodeBlock> list = new LinkedList<>();
        HashSet<Long> history = new HashSet<Long>();
        for(CodeBlock bb: bbm.getCodeBlocksContaining(f.getBody(), monitor)){
            Long bbAddr = bb.getFirstStartAddress().getOffset();
            if(history.contains(bbAddr)){
                continue;
            }

            history.add(bbAddr);
            list.add(bb);
        }
        return list;
    }

}