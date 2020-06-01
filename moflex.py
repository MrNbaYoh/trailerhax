from struct import pack
from bitarray import bitarray
from bitarray.util import int2ba

SYNCHRO_HEADER_MAGIC = b"\x4C\x32"
def makeSynchoHeader(timestamp, size=0x1000):
    assert(size > 0)
    checksum = 0xAAAA ^ (timestamp & 0xFFFF) ^ ((timestamp >> 16) & 0xFFFF) ^ ((timestamp >> 32) & 0xFFFF) ^ ((timestamp >> 48) & 0xFFFF)

    bin  = bytearray()
    bin += SYNCHRO_HEADER_MAGIC     #16bits magic value
    bin += pack(">H", checksum)     #16bits BE timestamp checksum
    bin += pack(">Q", timestamp)    #64bits BE timestamp
    bin += pack(">H", size-1)       #16bits BE packet size-1

    return bin

def setSynchroHeaderSize(synchroHeader, size):
    assert(size > 0)
    binsize = pack(">H", size-1)    #16bits BE packet size-1
    synchroHeader[0xC] = binsize[0]
    synchroHeader[0xD] = binsize[1]

def makeVariableByte(value):
    assert(0 <= value < 2**28)
    bin = bytearray()

    bin = pack("B", value & 0x7F)
    remaining = value >> 7

    #if there's more than 7bits to write
    while(remaining):
        current = remaining & 0x7F
        remaining = remaining >> 7
        #bit 8 indicates there's still another 7bit value to read afterwards
        bin = pack("B", 0x80 | current) + bin

    return bin

#same as makeVariableByte but force the result to be on 4 bytes for more determinism
def makeVariableByte4Bytes(value):
    assert(0 <= value < 2**28)
    bin = bytearray()

    bin = pack("B", value & 0x7F)
    remaining = value >> 7

    for i in range(3):
        current = remaining & 0x7F
        remaining = remaining >> 7
        #bit 8 indicates there's still another 7bit value to read afterwards
        bin = pack("B", 0x80 | current) + bin

    return bin


SYNCHRO_CHUNK_TYPE_VIDEO = 0x1
VIDEO_CODEC_MOBICLIP = 0x0
def makeVideoSynchroChunk(streamIndex, fpsRate, fpsScale, width, height, pelRatioRate, pelRatioScale):
    bin  = bytearray()
    bin += pack("B", SYNCHRO_CHUNK_TYPE_VIDEO)  #8bits stream type (trivial variable byte)
    bin += pack("B", 0xC)                       #8bits chunk size  (trivial variable byte)
    bin += pack("B", streamIndex)               #8bits stream index
    bin += pack("B", VIDEO_CODEC_MOBICLIP)      #8bits video codec
    bin += pack(">H", fpsRate)
    bin += pack(">H", fpsScale)
    bin += pack(">H", width)
    bin += pack(">H", height)
    bin += pack("B", pelRatioRate)
    bin += pack("B", pelRatioScale)

    return bin

SYNCHRO_CHUNK_TYPE_AUDIO    = 0x2
AUDIO_CODEC_TYPE_FASTAUDIO  = 0x0
AUDIO_CODEC_TYPE_IMAADPCM   = 0x1
AUDIO_CODEC_TYPE_PCM16      = 0x2
def makeAudioSynchroChunk(streamIndex, codec, rate, nbChannel):
    bin  = bytearray()
    bin += pack("B", SYNCHRO_CHUNK_TYPE_AUDIO)  #8bits stream type (trivial variable byte)
    bin += pack("B", 0x6)                       #8bits chunk size  (trivial variable byte)
    bin += pack("B", streamIndex)               #8bits stream index
    bin += pack("B", codec)                     #8bits audio codec
    bin += pack("x")                            #8bits unused/padding
    bin += pack(">H", rate)                     #16bits BE rate/frequency
    bin += pack("B", nbChannel-1)               #8bits channel count

    return bin

SYNCHRO_CHUNK_TYPE_TIMELINE = 0x4
def makeTimelineSynchroChunk(streamIndex, associatedStreamIndex):
    bin  = bytearray()
    bin += pack("B", SYNCHRO_CHUNK_TYPE_TIMELINE)   #8bits stream type (trivial variable byte)
    bin += pack("B", 0x2)                           #8bits chunk size  (trivial variable byte)
    bin += pack("B", streamIndex)                   #8bits stream index
    bin += pack("B", associatedStreamIndex)         #8bits stream index associtated to the timeline stream

    return bin

SYNCHRO_CHUNK_TYPE_END = 0x0
def makeEndSynchroChunk(data = b""):
    bin  = bytearray()
    bin += pack("B", SYNCHRO_CHUNK_TYPE_END)        #8bits stream type (trivial variable byte)
    bin += makeVariableByte(len(data))              #variable byte chunk size
    bin += data                                     #skipped data

    return bin

def makeEndSynchroChunk4BytesSize(data):
    bin  = bytearray()
    bin += pack("B", SYNCHRO_CHUNK_TYPE_END)        #8bits stream type (trivial variable byte)
    bin += makeVariableByte4Bytes(len(data))        #32bits variable byte chunk size
    bin += data                                     #skipped data

    return bin

def makeDataBlock(synchroCounter, isPacketSizeVariable = 1, isPacketCountingEnabled = 0, packetCounter = 0):
    assert(0 <= isPacketSizeVariable <= 1)
    assert(0 <= isPacketCountingEnabled <= 1)
    assert(0 <=  synchroCounter < 2**6)
    flags = isPacketSizeVariable | (isPacketCountingEnabled << 1)

    bin  = bytearray()
    bin += pack("B", (synchroCounter << 2) | flags) #8bits flags and synchro counter
    if(isPacketCountingEnabled):
        bin += pack(">H", packetCounter)            #16bits BE optional packet counter

    return bin

def makeEp(data, streamIndex, isFrameEnd, frameType):
    assert(0 <= streamIndex < 2**64)
    assert(0 <= frameType < 2**64)
    assert(0 <= len(data) <= 2**13)
    if(len(data) == 0):
        return b"\x00"

    bits  = bitarray(endian = 'big')

    #put as many zeros as the number of bits needed for the stream index, minus one
    streamIndexNbBits = streamIndex.bit_length()
    bits += bitarray((streamIndexNbBits-1)*"0" + "1")
    #then put the index
    bits += int2ba(streamIndex, length=None, endian='big')   #stream index associtated to the data

    bits.append(isFrameEnd)         #are those data the end of the current frame
    if(isFrameEnd):
        #put as many zeros as the number of bits needed for the frame type, minus one
        frameTypeNbBits = frameType.bit_length() + 1
        bits += bitarray((frameTypeNbBits-1)*"0" + "1")
        #then put the frame type
        bits += int2ba(frameType, length=None, endian='big')

        bits.append(0)                  #unknown
        bits.append(1)                  #need to write a value of size nb_zero*2+28 bits afterwards, so just nullify nb_zero

        bits += bitarray("0"*28)        #unknown

    #put data len minus one on 13 bits
    bits += int2ba(len(data) - 1, length=13, endian='big')

    return bits.tobytes() + data
