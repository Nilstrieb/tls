use byteorder::{BigEndian as B, ReadBytesExt, WriteBytesExt};
use std::{
    fmt::Debug,
    io::{self, Read, Write},
    marker::PhantomData,
    num::TryFromIntError,
    ops::{Deref, DerefMut},
};

pub struct FrameReader<R> {
    read: R,
    pub is_hello_retry_request: bool,
}

impl<R> FrameReader<R> {
    pub fn new(read: R) -> Self {
        FrameReader {
            read,
            is_hello_retry_request: false,
        }
    }
}

impl<R> Deref for FrameReader<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}

impl<R> DerefMut for FrameReader<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.read
    }
}

/// ```ignore
/// proto_struct! {}
/// ```
macro_rules! proto_struct {
    {$(#[$meta:meta])* pub struct $name:ident {
        $(
            pub $field_name:ident : $field_ty:ty,
        )*
    }} => {
        $(#[$meta])*
        pub struct $name {
            $(
                pub $field_name: $field_ty,
            )*
        }


        impl crate::proto::ser_de::Value for $name {
            fn write<W: std::io::Write>(&self, mut w: &mut W) -> std::io::Result<()> {
                $(
                    crate::proto::ser_de::Value::write(&self.$field_name, &mut w)?;
                )*
                Ok(())
            }

            fn read<R: std::io::Read>(r: &mut $crate::proto::ser_de::FrameReader<R>) -> crate::Result<Self> {
                let ( $( $field_name ),* ) = ($( { crate::proto::ser_de::discard!($field_name); crate::proto::ser_de::Value::read(r)? } ),*);

                Ok(Self {
                    $(
                        $field_name,
                    )*
                })
            }

            fn byte_size(&self) -> usize {
                $( self.$field_name.byte_size() + )* 0
            }
        }
    };
}

pub(crate) use proto_struct;

/// ```ignore
/// proto_enum! {}
/// ```
macro_rules! proto_enum {
    {$(#[$meta:meta])* pub enum $name:ident: $discr_ty:ty $( ,(length: $len_ty:ty) )? {
        $(
            $KindName:ident $({
                $(
                    $field_name:ident : $field_ty:ty,
                )*
            })? = $discriminant:expr,
        )*
    }} => {
        $(#[$meta])*
        pub enum $name {
            $(
                $KindName $({
                    $(
                        $field_name: $field_ty,
                    )*
                })?,
            )*
        }

        impl crate::proto::ser_de::Value for $name {
            fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
                w.flush()?;
                //eprintln!("{}", stringify!($name));
                mod discr_consts {
                    $(
                        #[allow(non_upper_case_globals)]
                        pub(super) const $KindName: $discr_ty = $discriminant;
                    )*
                }

                let write_len = |_w: &mut W, _len: usize| -> io::Result<()> {
                    _w.flush()?;
                    //eprintln!("length");
                    $(
                        <$len_ty>::try_from(_len).unwrap().write(_w)?;
                    )?
                    Ok(())
                };

                match self {
                    $(
                        Self::$KindName $( {
                            $( $field_name, )*
                        } )? => {
                            let byte_size = $($( $field_name.byte_size() + )*)? 0;

                            crate::proto::ser_de::Value::write(&discr_consts::$KindName, w)?;
                            write_len(w, byte_size)?;

                            let w = &mut crate::proto::ser_de::MeasuringWriter(0, w);

                            $($(
                                w.flush()?;
                                //eprintln!("{}", stringify!($field_name));
                                crate::proto::ser_de::Value::write($field_name, w)?;
                            )*)?

                            debug_assert_eq!(w.0, byte_size);

                            Ok(())
                        }
                    )*
                }
            }

            fn read<R: Read>(r: &mut $crate::proto::ser_de::FrameReader<R>) -> crate::Result<Self> {
                mod discr_consts {
                    #[allow(unused_imports)]
                    use super::*;
                    pub type Type = $discr_ty;
                    $(
                        #[allow(non_upper_case_globals)]
                        pub(super) const $KindName: $discr_ty = $discriminant;
                    )*
                }

                let kind: discr_consts::Type = crate::proto::ser_de::Value::read(r)?;

                $(
                    let _len = <$len_ty>::read(r)?;
                )?

                match kind {
                    $(
                        discr_consts::$KindName => {
                            $($(
                                let $field_name = crate::proto::ser_de::Value::read(r)?;
                            )*)?

                            Ok(Self::$KindName $({
                                $(
                                    $field_name,
                                )*
                            })*)
                        },
                    )*

                    _ => Err(ErrorKind::InvalidFrame(Box::new(format!("invalid discriminant for {}: 0x{kind:x?}", stringify!($name)))).into()),
                }
            }

            fn byte_size(&self) -> usize {
                mod discr_consts {
                    $(
                        #[allow(non_upper_case_globals)]
                        pub(super) const $KindName: $discr_ty = $discriminant;
                    )*
                }

                $( <$len_ty>::default().byte_size() + )? match self {
                    $(
                        Self::$KindName $( {
                            $( $field_name, )*
                        } )? => {
                            $( $( $field_name.byte_size() + )* )? discr_consts::$KindName.byte_size()
                        }
                    )*
                }
            }
        }
    };
}
pub(crate) use proto_enum;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Todo;

impl Value for Todo {
    fn write<W: Write>(&self, _: &mut W) -> io::Result<()> {
        todo!()
    }

    fn read<R: Read>(_: &mut FrameReader<R>) -> crate::Result<Self> {
        todo!()
    }

    fn byte_size(&self) -> usize {
        todo!()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct List<T, Len>(Vec<T>, PhantomData<Len>);

impl<T, Len: Value> From<Vec<T>> for List<T, Len> {
    fn from(value: Vec<T>) -> Self {
        Self(value, PhantomData)
    }
}

impl<T, Len> AsRef<[T]> for List<T, Len> {
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T: Debug, Len> Debug for List<T, Len> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<T: Value, Len: Value + Into<usize> + TryFrom<usize> + Default> Value for List<T, Len> {
    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        let remaining_byte_size = Len::read(r)?.into();
        Self::read_for_byte_length(remaining_byte_size, r)
    }
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let byte_size = self.0.iter().map(Value::byte_size).sum::<usize>();
        Len::write(
            &byte_size
                .try_into()
                .unwrap_or_else(|_| panic!("list is too large for domain: {}", self.0.len())),
            w,
        )?;
        for elem in &self.0 {
            elem.write(w)?;
        }
        Ok(())
    }
    fn byte_size(&self) -> usize {
        Len::byte_size(&Default::default()) + self.0.iter().map(Value::byte_size).sum::<usize>()
    }
}

impl<T: Value, Len: Value + Into<usize> + TryFrom<usize> + Default> List<T, Len> {
    pub fn read_for_byte_length<R: Read>(
        mut remaining_byte_size: usize,
        r: &mut FrameReader<R>,
    ) -> crate::Result<Self> {
        let mut v = Vec::new();
        while remaining_byte_size > 0 {
            let value = T::read(r)?;
            remaining_byte_size -= value.byte_size();
            v.push(value);
        }
        Ok(Self(v, PhantomData))
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

pub trait Value: Sized + std::fmt::Debug {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()>;
    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self>;
    fn byte_size(&self) -> usize;
}

impl<V: Value, const N: usize> Value for [V; N] {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        self.iter().try_for_each(|v| Value::write(v, w))
    }
    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        // ugly :(
        let mut values = Vec::with_capacity(N);
        for _ in 0..N {
            let value = V::read(r)?;
            values.push(value);
        }
        Ok(values.try_into().unwrap())
    }
    fn byte_size(&self) -> usize {
        self.iter().map(Value::byte_size).sum()
    }
}

impl Value for u8 {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u8(*self)
    }
    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        r.read_u8().map_err(Into::into)
    }
    fn byte_size(&self) -> usize {
        1
    }
}

impl Value for u16 {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u16::<B>(*self)
    }
    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        r.read_u16::<B>().map_err(Into::into)
    }
    fn byte_size(&self) -> usize {
        2
    }
}

impl Value for u32 {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u32::<B>(*self)
    }

    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        r.read_u32::<B>().map_err(Into::into)
    }

    fn byte_size(&self) -> usize {
        4
    }
}

impl<T: Value, U: Value> Value for (T, U) {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        T::write(&self.0, w)?;
        T::write(&self.0, w)?;
        Ok(())
    }

    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        Ok((T::read(r)?, U::read(r)?))
    }

    fn byte_size(&self) -> usize {
        self.0.byte_size() + self.1.byte_size()
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[allow(non_camel_case_types)]
pub struct u24(u32);

impl Value for u24 {
    fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_u24::<B>(self.0)
    }

    fn read<R: Read>(r: &mut FrameReader<R>) -> crate::Result<Self> {
        r.read_u24::<B>().map_err(Into::into).map(u24)
    }

    fn byte_size(&self) -> usize {
        3
    }
}

impl TryFrom<usize> for u24 {
    type Error = TryFromIntError;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let value = u32::try_from(value)?;
        if value > 2_u32.pow(24) {
            return Err(u32::try_from(usize::MAX).unwrap_err());
        }
        Ok(u24(value))
    }
}

pub(crate) struct MeasuringWriter<W>(pub(crate) usize, pub(crate) W);

impl<W: Write> Write for MeasuringWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.1.write(buf)?;
        self.0 += len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.1.flush()
    }
}

macro_rules! discard {
    ($($tt:tt)*) => {};
}
pub(crate) use discard;
