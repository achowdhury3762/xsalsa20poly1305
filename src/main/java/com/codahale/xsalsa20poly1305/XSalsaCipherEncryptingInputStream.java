package com.codahale.xsalsa20poly1305;

import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;

public class XSalsaCipherEncryptingInputStream extends InputStream {
  private final InputStream inputStream;
  private final XSalsa20Engine xsalsa20;
  private final Poly1305 poly1305 = new Poly1305();
  private boolean macWritten = false;

  public XSalsaCipherEncryptingInputStream(SecretBox secretBox,
                                           final InputStream inputStream, byte[] nonce) {
    this.inputStream = inputStream;
    this.xsalsa20 = secretBox.initSalsaEngine(true, nonce);
    final byte[] sk = secretBox.createSubKey(xsalsa20);
    poly1305.init(new KeyParameter(sk));
  }

  @Override
  public int read() throws IOException {
    final byte[] buffer = new byte[1];

    while (true) {
      int length = read(buffer, 0, buffer.length);
      if (length == -1) {
        return -1;
      } else if (length != 0) {
        return buffer[0];
      }
      Thread.yield();
    }
  }

  @Override
  public void close() throws IOException {
    inputStream.close();
  }

  @Override
  public int read(byte[] buffer) throws IOException {
    return read(buffer, 0, buffer.length);
  }

  @Override
  public int read(byte[] buffer, int byteOffset, int byteCount) throws IOException {
    if (macWritten) {
      return -1;
    }

    int length = inputStream.read(buffer, byteOffset, byteCount);
    if (length == -1) {
      poly1305.doFinal(buffer, byteOffset);
      macWritten = true;
      return poly1305.getMacSize();
    } else if (length > 0) {
      xsalsa20.processBytes(buffer, byteOffset, length, buffer, byteOffset);
      poly1305.update(buffer, byteOffset, length);
    }
    return length;
  }
}
