#!/usr/bin/env python3
# Self-contained EVM bytecode analyzer for H6 exchange pools.
# Usage: python3 -I analyzer_evm.py <file-with-hex-bytecode>
# - pure-python keccak256 (no deps)
# - disassembles, maps the known H4 interface selectors -> code offset via the solc dispatcher
# - dumps each target function's disassembly and flags CALL-before-SSTORE (reentrancy heuristic)

import sys, re, json

# ---------- pure-python keccak-256 ----------
_RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
_R=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
def _rol(x,n): return ((x<<n)|(x>>(64-n)))&0xFFFFFFFFFFFFFFFF
def _keccak_f(st):
    for rc in _RC:
        C=[st[x]^st[x+5]^st[x+10]^st[x+15]^st[x+20] for x in range(5)]
        D=[C[(x+4)%5]^_rol(C[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(0,25,5): st[x+y]^=D[x]
        B=[0]*25
        for x in range(5):
            for y in range(5): B[y+((2*x+3*y)%5)*5]=_rol(st[x+y*5],_R[x][y])
        for x in range(5):
            for y in range(0,25,5):
                st[x+y]=B[x+y]^((~B[(x+1)%5+y])&B[(x+2)%5+y])
        st[0]^=rc
    return st
def keccak256(data:bytes)->bytes:
    rate=136; st=[0]*25; pad=data+b'\x01'+b'\x00'*((-len(data)-1)%rate)+b'\x80'
    if len(pad)%rate: pad=data+b'\x01'; pad+=b'\x00'*((-len(pad))%rate); pad=bytearray(pad); pad[-1]|=0x80; pad=bytes(pad)
    for off in range(0,len(pad),rate):
        blk=pad[off:off+rate]
        for i in range(rate//8):
            st[i]^=int.from_bytes(blk[i*8:i*8+8],'little')
        _keccak_f(st)
    out=b''.join(int(st[i]).to_bytes(8,'little') for i in range(25))
    return out[:32]
def sel(sig): return keccak256(sig.encode())[:4].hex()

# ---------- opcode table ----------
OPS={0x00:'STOP',0x01:'ADD',0x02:'MUL',0x03:'SUB',0x04:'DIV',0x05:'SDIV',0x06:'MOD',0x07:'SMOD',
0x08:'ADDMOD',0x09:'MULMOD',0x0a:'EXP',0x0b:'SIGNEXTEND',0x10:'LT',0x11:'GT',0x12:'SLT',0x13:'SGT',
0x14:'EQ',0x15:'ISZERO',0x16:'AND',0x17:'OR',0x18:'XOR',0x19:'NOT',0x1a:'BYTE',0x1b:'SHL',0x1c:'SHR',
0x1d:'SAR',0x20:'KECCAK256',0x30:'ADDRESS',0x31:'BALANCE',0x32:'ORIGIN',0x33:'CALLER',0x34:'CALLVALUE',
0x35:'CALLDATALOAD',0x36:'CALLDATASIZE',0x37:'CALLDATACOPY',0x38:'CODESIZE',0x39:'CODECOPY',0x3a:'GASPRICE',
0x3b:'EXTCODESIZE',0x3c:'EXTCODECOPY',0x3d:'RETURNDATASIZE',0x3e:'RETURNDATACOPY',0x3f:'EXTCODEHASH',
0x40:'BLOCKHASH',0x41:'COINBASE',0x42:'TIMESTAMP',0x43:'NUMBER',0x44:'PREVRANDAO',0x45:'GASLIMIT',
0x46:'CHAINID',0x47:'SELFBALANCE',0x48:'BASEFEE',0x50:'POP',0x51:'MLOAD',0x52:'MSTORE',0x53:'MSTORE8',
0x54:'SLOAD',0x55:'SSTORE',0x56:'JUMP',0x57:'JUMPI',0x58:'PC',0x59:'MSIZE',0x5a:'GAS',0x5b:'JUMPDEST',
0xf0:'CREATE',0xf1:'CALL',0xf2:'CALLCODE',0xf3:'RETURN',0xf4:'DELEGATECALL',0xf5:'CREATE2',
0xfa:'STATICCALL',0xfd:'REVERT',0xfe:'INVALID',0xff:'SELFDESTRUCT'}
for n in range(1,33): OPS[0x5f+n]='PUSH%d'%n
for n in range(1,17): OPS[0x7f+n]='DUP%d'%n
for n in range(1,17): OPS[0x8f+n]='SWAP%d'%n
for n in range(0,5):  OPS[0xa0+n]='LOG%d'%n

def disasm(code):
    out=[]; i=0; n=len(code)
    while i<n:
        op=code[i]; name=OPS.get(op,'UNK_%02x'%op); arg=None
        if 0x60<=op<=0x7f:
            k=op-0x5f; arg=code[i+1:i+1+k].hex(); i+=1+k
        else: i+=1
        out.append((i-(1+(len(arg)//2) if arg else 1), op, name, arg))
    # fix pc calc
    out2=[]; pc=0; i=0
    while i<n:
        op=code[i]; name=OPS.get(op,'UNK_%02x'%op); arg=None; sz=1
        if 0x60<=op<=0x7f:
            k=op-0x5f; arg=code[i+1:i+1+k].hex(); sz=1+k
        out2.append((pc,op,name,arg)); pc+=sz; i+=sz
    return out2

def parse_dispatcher(ins):
    # map selector(hex8) -> jumpdest(int) from PUSH4 .. EQ/GT .. PUSH2 dest .. JUMPI pattern
    m={}
    for idx,(pc,op,name,arg) in enumerate(ins):
        if name=='PUSH4' and arg:
            # look ahead a few instrs for a PUSH2 then JUMPI
            for j in range(idx+1, min(idx+8,len(ins))):
                if ins[j][2]=='PUSH2' and ins[j][3]:
                    # confirm a JUMPI shortly after
                    for k in range(j+1,min(j+3,len(ins))):
                        if ins[k][2]=='JUMPI':
                            m.setdefault(arg,int(ins[j][3],16)); break
                    break
    return m

def window(ins, start_pc, count=160):
    # linear disassembly from the instruction at start_pc
    idx=next((i for i,x in enumerate(ins) if x[0]==start_pc), None)
    if idx is None: return []
    return ins[idx:idx+count]

def main():
    raw=open(sys.argv[1]).read().strip()
    # accept either raw hex or JSON with deployed_bytecode
    if raw.startswith('{'):
        j=json.loads(raw)
        src=j.get('source_code') or j.get('sourceCode')
        if src:
            print("=== VERIFIED SOURCE FOUND (len %d) ===\n"%len(src)); print(src[:20000]); return
        raw=j.get('deployed_bytecode') or j.get('deployedBytecode') or j.get('creation_bytecode') or ''
    hx=re.sub(r'[^0-9a-fA-F]','', raw)
    if hx.startswith('0x') or hx.startswith('0X'): hx=hx[2:]
    if len(hx)%2: hx=hx[:-1]
    code=bytes.fromhex(hx)
    ins=disasm(code)
    print("bytes:",len(code),"instructions:",len(ins))

    names={'provideLiquidity(uint256)':None,'withdrawLiquidity(uint256)':None,'swapForEth(uint256)':None,
           'swapForERC20Token()':None,'estimateSwapForEth(uint256)':None,'estimateSwapForERC20Token(uint256)':None,
           'getMyLiquidityPositions()':None,'estimateEthToProvide(uint256)':None,'estimateERC20TokenToProvide(uint256)':None}
    selmap={sel(s):s for s in names}
    disp=parse_dispatcher(ins)
    print("\n=== dispatcher selector -> jumpdest ===")
    for s,d in disp.items():
        lbl=selmap.get(s,'?')
        print(f"  0x{s} -> 0x{d:x}  {lbl}")

    # global CALL / SSTORE / value-call markers
    calls=[(pc) for (pc,op,nm,arg) in ins if nm in('CALL','CALLCODE')]
    sstores=[pc for (pc,op,nm,arg) in ins if nm=='SSTORE']
    print(f"\nCALL sites: {[hex(x) for x in calls]}")
    print(f"SSTORE sites: {[hex(x) for x in sstores]}")

    # dump the money functions
    for want in ['swapForEth(uint256)','swapForERC20Token()','withdrawLiquidity(uint256)','provideLiquidity(uint256)']:
        s=sel(want); d=disp.get(s)
        print(f"\n===== {want}  sel=0x{s}  entry={'0x%x'%d if d else 'NOT FOUND'} =====")
        if not d: continue
        for (pc,op,nm,arg) in window(ins,d,220):
            mark=''
            if nm in('CALL','CALLCODE'): mark='   <<< EXTERNAL CALL (sends ETH)'
            if nm=='SSTORE': mark='   <<< STATE WRITE'
            if nm in('RETURN','STOP','REVERT') : mark='   <<< end'
            print(f"  0x{pc:04x} {nm}{' 0x'+arg if arg else ''}{mark}")

if __name__=='__main__': main()
