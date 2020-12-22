# trailerhax
trailerhax is an exploit for the 3DS eShop movie player.
The exploit uses [SSLoth](https://github.com/MrNbaYoh/3ds-ssloth) to bypass the SSL/TLS certificate validation, this allows to spoof the official eShop servers. It is provided as a [mitmproxy](https://mitmproxy.org) script.

*Note:* this is only a PoC meant to execute a ROP-chain in the 3DS eShop application (EUR-only).

## How does it work?
trailerhax exploits a vulnerability in the audio decoder of the eShop movie player. When parsing a `.moflex` video, the application creates an audio decoder object based on the audio codec of the movie. Here's the associated piece of code:
```
void create_audio_decoder(u8 codec, ..., audio_decoder** out_decoder) {
    if(codec == fastaudio) {
      decoder = create_fastaudio_decoder(...);
      *out_decoder = decoder;
    }
    else if(codec == imaadpcm) {
      decoder = create_imaadpcm_decoder(...);
      *out_decoder = decoder;
    }
    else if(codec == pcm16)
      decoder = *out_decoder; // *out_decoder is not initialized!

   if(decoder)
      decoder->init(); //if decoder is controlled this gives an arbitrary jump!
}
```

The player is supposed to accept 3 different audio codecs: `IMA-ADPCM`, `fastaudio` & `PCM16`. While a decoder is actually needed for both the `fastaudio` and `IMA-ADPCM` cases, raw `PCM16` data do not need to be decoded.

Thus, no audio decoder object is created in the `PCM16` case, and the application directly uses the `out_decoder` parameter to initialize the `decoder` variable. However, `out_decoder` points to uninitialized data and `decoder` is then used for a virtual function call. This gives us an arbitrary jump if we can spray the heap and control the uninitialized data `out_decoder` points to.

To spray the heap, we replace the JPEG screenshots displayed on title information pages with buffers full of pointers to the `moflex` data in memory. Those buffers are freed when the movie starts playing, so hopefully the video player object is allocated on the freed screenshot memory chunks and `out_decoder` ends up being set to our custom pointer.
