package net.codejava.javaee;
import java.util.Scanner;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.SimpleHashRequest;
import org.apache.shiro.crypto.hash.format.DefaultHashFormatFactory;
import org.apache.shiro.crypto.hash.format.HashFormat;
import org.apache.shiro.crypto.hash.format.HashFormatFactory;

import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat;
import org.apache.shiro.util.ByteSource;


/**
 * Commandline line utility to hash data such as strings, passwords, resources (files, urls, etc).
 * <p/>
 * Usage:
 * <pre>
 * java -jar shiro-tools-hasher<em>-version</em>-cli.jar
 * </pre>
 * This will print out all supported options with documentation.
 *
 * @since 1.2
 */
public final class Hasher2 {

	private static final String HEX_PREFIX = "0x";

	private static final String DEFAULT_PASSWORD_ALGORITHM_NAME = "SHA-256";
	private static final int DEFAULT_GENERATED_SALT_SIZE = 128;
	private static final int DEFAULT_PASSWORD_NUM_ITERATIONS = 500000;

	private static final HashFormatFactory HASH_FORMAT_FACTORY = new DefaultHashFormatFactory();

	public static void main(String[] args) {
	
		
	}
	private static ByteSource getSalt(String saltString, String saltBytesString, boolean generateSalt, int generatedSaltSize) {

		if (saltString != null) {
			if (generateSalt || (saltBytesString != null)) {
				throw new IllegalArgumentException();
			}
			return ByteSource.Util.bytes(saltString);
		}

		if (saltBytesString != null) {
			if (generateSalt) {
				throw new IllegalArgumentException();
			}

			String value = saltBytesString;
			boolean base64 = true;
			if (saltBytesString.startsWith(HEX_PREFIX)) {
				//hex:
				base64 = false;
				value = value.substring(HEX_PREFIX.length());
			}
			byte[] bytes;
			if (base64) {
				bytes = Base64.decode(value);
			} else {
				bytes = Hex.decode(value);
			}
			return ByteSource.Util.bytes(bytes);
		}

		if (generateSalt) {
			SecureRandomNumberGenerator generator = new SecureRandomNumberGenerator();
			int byteSize = generatedSaltSize / 8; 
			return generator.nextBytes(byteSize);
		}
		return null;
	}

	public static String readPassword(String pass) {
		
		char[] first=pass.toCharArray();
		
		
		//String algorithm = null; //user unspecified
		//int iterations = 0; //0 means unspecified by the end-user

		//char[] passwordChars = null;
		String saltString = null;
		String saltBytesString = null;
		boolean generateSalt = true;
		int generatedSaltSize = DEFAULT_GENERATED_SALT_SIZE;
		String privateSaltString = null;
		String privateSaltBytesString = null;
		

		String formatString = null;
		

		
			generateSalt = true;
			Object source;
			
			source = first;
			String algorithm = DEFAULT_PASSWORD_ALGORITHM_NAME;                                          
			int iterations = DEFAULT_PASSWORD_NUM_ITERATIONS;

			ByteSource publicSalt = getSalt(saltString, saltBytesString, generateSalt, generatedSaltSize);
			ByteSource privateSalt = getSalt(privateSaltString, privateSaltBytesString, false, generatedSaltSize);
			HashRequest hashRequest = new SimpleHashRequest(algorithm, ByteSource.Util.bytes(source), publicSalt, iterations);

			DefaultHashService hashService = new DefaultHashService();
			hashService.setPrivateSalt(privateSalt);
			Hash hash = hashService.computeHash(hashRequest);
			
			formatString = Shiro1CryptFormat.class.getName();
			
			HashFormat format = HASH_FORMAT_FACTORY.getInstance(formatString);
		
			String output = format.format(hash);

			System.out.println(output);
			return output;
	}
}
