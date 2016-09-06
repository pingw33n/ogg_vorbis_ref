extern crate libc;
extern crate ogg_sys;
extern crate vorbis_sys;

use libc::*;
use ogg_sys::*;
use std::ffi::CStr;
use std::io::{Error, ErrorKind, Read, Result};
use std::slice;
use std::mem;
use vorbis_sys::*;

pub struct OggRefDecoder<R> {
    reader: R,
    buf_len: usize,
    sync: Box<ogg_sync_state>,
    eos: bool,
    stream: Option<OggDecoderStream>,
}

impl<R: Read> OggRefDecoder<R> {
    pub fn new(reader: R, buf_len: usize) -> Self {
        let mut sync = Box::new(unsafe { mem::zeroed() });
        assert_eq!(unsafe { ogg_sync_init(&mut *sync) }, 0);

        OggRefDecoder {
            reader: reader,
            buf_len: buf_len,
            sync: sync,
            eos: false,
            stream: None,
        }
    }

    pub fn reset(&mut self) -> Result<()> {
        self.stream = None;

        let mut page = Box::new(unsafe { mem::zeroed() });
        try!(Self::page_out(&mut self.reader, &mut self.sync, &mut page, self.buf_len));

        let mut state = Box::new(unsafe { mem::zeroed::<ogg_stream_state>() });
        unsafe { assert_eq!(ogg_stream_init(&mut *state, ogg_page_serialno(&mut *page)), 0); }
        try!(Self::page_in(&mut *state, &mut *page));

        self.stream = Some(OggDecoderStream {
            page: page,
            state: state,
            packet: Box::new(unsafe { mem::zeroed() }),
        });
        Ok(())
    }

    pub fn next_packet(&mut self) -> Result<bool> {
        if self.stream.is_none() {
            try!(self.reset());
        }

        loop {
            if self.eos {
                return Ok(false);
            }
            let mut stream = self.stream.as_mut().unwrap();
            // Set no-packet condition.
            stream.packet.packet = unsafe { mem::zeroed() };
            let result = unsafe { ogg_stream_packetout(&mut *stream.state, &mut *stream.packet) };
            if result <= 0 {
                try!(Self::page_out(&mut self.reader, &mut *self.sync, &mut *stream.page, self.buf_len));
                try!(Self::page_in(&mut *stream.state, &mut *stream.page));
            } else {
                self.eos = unsafe { ogg_page_eos(&*stream.page) } != 0;
                return Ok(true);
            }
        }
    }

    pub fn raw_packet(&self) -> &ogg_packet {
        if let Some(stream) = self.stream.as_ref() {
            if !stream.packet.packet.is_null() {
                return &stream.packet;
            }
        }
        panic!();
    }

    pub fn raw_packet_mut(&mut self) -> &mut ogg_packet {
        self.raw_packet();
        return &mut self.stream.as_mut().unwrap().packet;
    }

    pub fn packet_data(&self) -> &[u8] {
        let p = self.raw_packet();
        unsafe { slice::from_raw_parts(p.packet as *const u8, p.bytes as usize) }
    }

    pub fn is_eos(&self) -> bool {
        self.eos
    }

    fn page_out(reader: &mut R, sync: &mut ogg_sync_state, page: &mut ogg_page, buf_len: usize) -> Result<()> {
        while unsafe { ogg_sync_pageout(sync, page) } != 1 {
            let buf = unsafe {
                slice::from_raw_parts_mut(ogg_sync_buffer(sync, buf_len as libc::c_long) as *mut u8, buf_len)
            };
            let read = try!(reader.read(buf));
            if read == 0 {
                return Err(Error::new(ErrorKind::UnexpectedEof, "Couldn't read Ogg page"));
            }
            unsafe { ogg_sync_wrote(sync, read as libc::c_long); }
        }
        Ok(())
    }

    fn page_in(state: &mut ogg_stream_state, page: &mut ogg_page) -> Result<()> {
        if unsafe { ogg_stream_pagein(state, page) } != 0 {
            Err(Error::new(ErrorKind::InvalidData, "Bad page"))
        } else {
            Ok(())
        }
    }
}

impl<T> Drop for OggRefDecoder<T> {
    fn drop(&mut self) {
        unsafe { ogg_sync_clear(&mut *self.sync); }
    }
}

struct OggDecoderStream {
    page: Box<ogg_page>,
    state: Box<ogg_stream_state>,
    packet: Box<ogg_packet>,
}

impl Drop for OggDecoderStream {
    fn drop(&mut self) {
        unsafe { ogg_stream_clear(&mut *self.state); }
    }
}

pub struct VorbisRefDecoder {
    info: Box<vorbis_info>,
    comment: Box<vorbis_comment>,
    header_packet_count: u32,
    synth: Option<DecoderSynthState>,
}

impl VorbisRefDecoder {
    pub fn new() -> Self {
        let mut info = Box::new(unsafe { mem::zeroed() });
        let mut comment = Box::new(unsafe { mem::zeroed() });
        unsafe {
            vorbis_info_init(&mut *info);
            vorbis_comment_init(&mut *comment);
        }
        VorbisRefDecoder {
            info: info,
            comment: comment,
            header_packet_count: 0,
            synth: None,
        }
    }

    pub fn decode_header(&mut self, packet: &mut ogg_packet) -> Result<()> {
        assert!(self.header_packet_count < 3);
        if unsafe { vorbis_synthesis_headerin(&mut *self.info, &mut *self.comment, packet) } < 0 {
            Err(Error::new(ErrorKind::InvalidData, "Couldn't decode header packet"))
        } else {
            self.header_packet_count += 1;
            if self.header_packet_count == 3 {
                self.synth = Some(DecoderSynthState::new(&mut *self.info));
            }
            Ok(())
        }
    }

    pub fn decode(&mut self, packet: &mut ogg_packet) -> Result<()> {
        let mut synth = self.synth.as_mut().unwrap();
        if unsafe { vorbis_synthesis(&mut *synth.block, packet) } != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "Couldn't synth packet"));
        }
        if unsafe { vorbis_synthesis_blockin(&mut *synth.dsp, &mut *synth.block) } != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "Couldn't blockin"));
        }

        synth.pcm_len = unsafe { vorbis_synthesis_pcmout(&mut *synth.dsp, &mut synth.pcm) } as usize;

        unsafe { vorbis_synthesis_read(&mut *synth.dsp, synth.pcm_len as i32); }

        Ok(())
    }

    pub fn channel_count(&self) -> usize {
        self.info.channels as usize
    }

    pub fn pcm(&self, channel: usize) -> &[f32] {
        assert!(channel < self.channel_count());
        let synth = self.synth.as_ref().unwrap();
        if synth.pcm_len != 0 {
            unsafe { slice::from_raw_parts(*synth.pcm.offset(channel as isize) as *const f32, synth.pcm_len) }
        } else {
            &[]
        }
    }

    pub fn pcm_len(&self) -> usize {
        self.synth.as_ref().unwrap().pcm_len
    }

    pub fn comment_vendor(&self) -> Option<&str> {
        let s = unsafe { CStr::from_ptr(self.comment.vendor) };
        s.to_str().ok()
    }

    pub fn comment_count(&self) -> usize {
        self.comment.comments as usize
    }

    pub fn comment(&self, index: usize) -> Option<&str> {
        assert!(index < self.comment_count());
        let s = unsafe { CStr::from_ptr(*self.comment.user_comments.offset(index as isize)) };
        s.to_str().ok()
    }
}

impl Drop for VorbisRefDecoder {
    fn drop(&mut self) {
        self.synth = None;
        unsafe {
            vorbis_comment_clear(&mut *self.comment);
            vorbis_info_clear(&mut *self.info);
        }
    }
}

struct DecoderSynthState {
    dsp: Box<vorbis_dsp_state>,
    block: Box<vorbis_block>,
    pcm: *mut *mut libc::c_float,
    pcm_len: usize,
}

impl DecoderSynthState {
    pub fn new(info: &mut vorbis_info) -> Self {
        let mut dsp = Box::new(unsafe { mem::zeroed() });
        if unsafe { vorbis_synthesis_init(&mut *dsp, info) } != 0 {
            panic!("Couldn't init vorbis");
        }

        let mut block = Box::new(unsafe { mem::zeroed() });
        if unsafe { vorbis_block_init(&mut *dsp, &mut *block) } != 0 {
            panic!("Couldn't init vorbis block");
        }

        DecoderSynthState {
            dsp: dsp,
            block: block,
            pcm: unsafe { mem::zeroed() },
            pcm_len: 0,
        }
    }
}

impl Drop for DecoderSynthState {
    fn drop(&mut self) {
        unsafe {
            vorbis_block_clear(&mut *self.block);
            vorbis_dsp_clear(&mut *self.dsp);
        }
    }
}

#[repr(C)]
struct mdct_lookup {
  n: c_int,
  log2n: c_int,

  trig: *mut c_float,
  bitrev: *mut c_int,

  scale: c_float,
}

extern {
    fn mdct_init(lookup: *mut mdct_lookup, n: c_int);
    fn mdct_backward(lookup: *mut mdct_lookup, inp: *mut c_float, out: *mut c_float);
    fn mdct_clear(lookup: *mut mdct_lookup);
}

pub struct MdctRef {
    lookup: Box<mdct_lookup>,
    len: usize,
}

impl MdctRef {
    pub fn new(len: usize) -> Self {
        let mut lookup = Box::new(unsafe { mem::zeroed() });
        unsafe { mdct_init(&mut *lookup, len as c_int); }
        MdctRef {
            lookup: lookup,
            len: len,
        }
    }

    pub fn inverse(&self, buf: &mut [f32]) {
        assert_eq!(buf.len(), self.len);
        unsafe {
            let l = mem::transmute::<&mdct_lookup, *mut mdct_lookup>(self.lookup.as_ref());
            mdct_backward(l, buf.as_mut_ptr(), buf.as_mut_ptr());
        }
    }
}

impl Drop for MdctRef {
    fn drop(&mut self) {
        unsafe {
            mdct_clear(&mut *self.lookup);
        }
    }
}