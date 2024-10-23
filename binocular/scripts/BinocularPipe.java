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

public class BinocularPipe extends GhidraScript{

    @Override
    public void run() throws Exception{
        String[] args = this.getScriptArgs();
        String rootPipePath = args[0];
        String recvPath = Paths.get(rootPipePath, "send").toString();
        String sendPath = Paths.get(rootPipePath, "recv").toString();

        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        LanguageDescription langDescript = currentProgram.getLanguage().getLanguageDescription();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        HashMap<Long, CodeBlock> basicBlocMap = new HashMap<>();

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
                if (id == 0){
                    running = false;
                }

                rpipe.read(buff, 0, 8);
                bbAddr = ByteBuffer.wrap(buff).getLong();

                rpipe.read(buff, 0, 8);
                funcAddr = ByteBuffer.wrap(buff).getLong();
            }

            response = this.handleCommand(id, bbAddr, funcAddr);
            
            if (response == null){
                continue;
            }

            res_size = response.length;

            try(BufferedOutputStream wpipe = new BufferedOutputStream(new FileOutputStream(new File(sendPath)))){
                // For some reasone theres always a leading null byte... :(
                ByteBuffer out_buff = ByteBuffer.allocate(res_size + 6);
                out_buff.order(ByteOrder.BIG_ENDIAN);
                out_buff.putChar((char)(id+1));
                out_buff.putInt(res_size);
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
        switch(id){
            case 2:
                return this.smokeTest().getBytes();
            case 4:
                return this.getBinaryName().getBytes();
            default:
                return null;
        }
    }

    public String smokeTest(){
        return "BINocular Test";
    }

    public String getBinaryName(){
        return currentProgram.getName();
    }

    public Address getEntryPoint(SymbolTable st, FunctionManager fm){
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

    public String getArchitecture(LanguageDescription ld){
        return ld.getProcessor().toString();
    }

    public Endian getEndianness(LanguageDescription ld){
        return ld.getEndian();
    }

    public int getBitness(LanguageDescription ld){
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

    public List<Function> getFunctionIterator(FunctionManager fm){
        LinkedList<Function> funcs = new LinkedList<>();
        for(Function f: fm.getFunctions(true)){
            funcs.add(f);
        }
        return funcs;
    }

    public DecompileResults decompile(DecompInterface decomp, Function f, ConsoleTaskMonitor monitor){
        return decomp.decompileFunction(f, 300, monitor);
    }



}