

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

// This class generate and print in a file a pair of RSA key for testing purpose.
// The keys simulate the keys of the BE

public class GenKeyPair {
	RSAPrivateKey privatekey;
	public static void main(String[] args) {

		RSAPublicKey publickey = null;

		RSAPrivateKey privatekey = null;

        /* Generate keypair. */
		try {
			System.out.println("Generating keys terminal...");
			KeyPairGenerator generator = null;
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			java.security.KeyPair keypair = generator.generateKeyPair();
			publickey = (RSAPublicKey) keypair.getPublic();
			privatekey = (java.security.interfaces.RSAPrivateKey) keypair.getPrivate();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		byte[] pkbufmod = getBytes(privatekey.getModulus());

		byte[] pkbufexp = getBytes(privatekey.getPrivateExponent());

		byte[] skbufmod = getBytes(publickey.getModulus());

		byte[] skbufexp = getBytes(publickey.getPublicExponent());

		// Print public key to class file
		File classFile = new File("src/TerminalKeys.java");
		printClassHEX(privatekey, publickey,(short) 0, (short)128, classFile );
		//printClass(privatekey, pkbufmod, pkbufexp, skbufmod, skbufexp, (short) 0, (short)128, classFile);
	}

	private static void printClassHEX(RSAPrivateKey pk, RSAPublicKey sk, short offset, short length, File f) {
		PrintWriter pw = null;
		try {
			pw = new PrintWriter(f);
			//pw.println("package tests;\n");
			pw.println("//AUTO-GENERATED FILE");
			pw.println("//DO NOT MODIFY");
			pw.println("public class TerminalKeys {");
			pw.print("\tpublic static final String modulus = ");
			pw.println("\""+pk.getModulus().toString(16)+"\";");

			pw.print("\tpublic static final String privateExponent = ");
			pw.println("\""+pk.getPrivateExponent().toString(16)+"\";");

			pw.print("\tpublic static final String publicExponent = ");
			pw.println("\""+sk.getPublicExponent().toString(10)+"\";");

			pw.print("\tpublic static final String privateEncoded = ");
			pw.println("\""+DatatypeConverter.printHexBinary(pk.getEncoded())+"\";");

			pw.print("\tpublic static final String publicEncoded = ");
			pw.println("\""+DatatypeConverter.printHexBinary(sk.getEncoded())+"\";");

			pw.println("}");


		} catch(IOException e) {
			System.out.println("An error occurred while writing to file " + f.getName());
		} finally {
			try {
				pw.close();
			} catch(Exception e) {
				System.out.println("An error occurred while closing file " + f.getName());
			}
		}
	}

	private static void printClassEncoded(RSAPrivateKey pk, RSAPublicKey sk, short offset, short length, File f) {
		PrintWriter pw = null;
		try {
			//System.out.println(pk);
			System.out.println(DatatypeConverter.printHexBinary(pk.getEncoded()));
			pw = new PrintWriter(f);
			//pw.println("package tests;\n");
			pw.println("//AUTO-GENERATED FILE");
			pw.println("//DO NOT MODIFY");
			pw.println("public class CardKeys {");
			pw.print("\tpublic static final String privateEncodedTerminal = ");
			pw.println("\""+DatatypeConverter.printHexBinary(pk.getEncoded())+"\";");

			pw.print("\tpublic static final String publicEncodedTerminal = ");
			pw.println("\""+DatatypeConverter.printHexBinary(sk.getEncoded())+"\";");

			pw.println("}");


		} catch(IOException e) {
			System.out.println("An error occurred while writing to file " + f.getName());
		} finally {
			try {
				pw.close();
			} catch(Exception e) {
				System.out.println("An error occurred while closing file " + f.getName());
			}
		}
	}

	private static void printClass(RSAPrivateKey pk, byte[] bufPriMod, byte[]bufPriExp, byte[] bufShaMod, byte[]bufShaExp, short offset, short length, File f) {
		PrintWriter pw = null;
		try {
			pw = new PrintWriter(f);
			//pw.println("package tests;\n");
			pw.println("//AUTO-GENERATED FILE");
			pw.println("//DO NOT MODIFY");
			pw.println("public class BEkeys {");
			pw.print("\tpublic static final byte[] privateKeyBEMod = ");
			pw.println(toByteArrayString(bufPriMod, offset, (short)bufPriMod.length));

			pw.print("\tpublic static final byte[] privateKeyBEExp = ");
			pw.print(toByteArrayString(bufPriExp, offset, (short)bufPriExp.length));

			pw.print("\tpublic static final byte[] publicKeyBEMod = ");
			pw.print(toByteArrayString(bufShaMod, offset, (short)bufShaMod.length));

			pw.print("\tpublic static final byte[] publicKeyBEExp = ");
			pw.print(toByteArrayString(bufShaExp, offset, (short)bufShaExp.length));
			pw.println("}");


		} catch(IOException e) {
			System.out.println("An error occurred while writing to file " + f.getName());
		} finally {
			try {
				pw.close();
			} catch(Exception e) {
				System.out.println("An error occurred while closing file " + f.getName());
			}
		}
	}



	private static void printFile(byte[] buf, short offset, short length, File f) {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(f);
			fos.write(buf, offset, length);
		} catch(IOException e) {
			System.out.println("An error occurred while writing to file " + f.getName());
		} finally {
			try {
				fos.close();
			} catch(Exception e) {
				System.out.println("An error occurred while closing file " + f.getName());
			}
		}
	}

	private static String toByteArrayString(byte[] buf, short offset, short length) {
		StringWriter sw = new StringWriter();
		short origOffset = offset;
		sw.append("new byte[] { ");
		for(;offset < length - 1; offset++) {
			if((offset - origOffset) % 8 == 0) sw.append("\n\t\t");
			sw.append(String.format("(byte) 0x%02x, ", buf[offset - origOffset]));
		}
		sw.append(String.format("(byte) 0x%02x};\n", buf[offset]));
		return sw.toString();
	}

	public static byte[] getBytes(BigInteger big) {
		byte[] data = big.toByteArray();
		if (data[0] == 0) {
			byte[] tmp = data;
			data = new byte[tmp.length - 1];
			System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
		}
		return data;
	}
}