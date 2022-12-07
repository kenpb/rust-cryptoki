// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Digest data

use crate::error::{Result, Rv};
use crate::mechanism::Mechanism;
use crate::session::Session;
use cryptoki_sys::*;
use std::convert::TryInto;

// See public docs on stub in parent mod.rs
#[inline(always)]
pub(super) fn digest(
    session: &Session,
    mechanism: &Mechanism,
    data: &[u8],
) -> Result<Vec<u8>> {
  let mut mechanism: CK_MECHANISM = mechanism.into();
  let mut digested_data_len = 32;

  unsafe {
    Rv::from(get_pkcs11!(session.client(), C_DigestInit)(
      session.handle(),
      &mut mechanism as CK_MECHANISM_PTR,
    ))
    .into_result()?;
  }

  unsafe {
    Rv::from(get_pkcs11!(session.client(), C_DigestUpdate)(
      session.handle(),
      data.as_ptr() as *mut u8,
      data.len().try_into()?,
    ))
    .into_result()?;
  }

  let mut digested_data = vec![0; 32];

  unsafe {
    Rv::from(get_pkcs11!(session.client(), C_DigestFinal)(
      session.handle(),
      digested_data.as_mut_ptr(),
      &mut digested_data_len,
    ))
    .into_result()?;
  }

  Ok(digested_data)
}
