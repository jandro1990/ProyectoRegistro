package net.codejava.javaee;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.DefaultParser;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.UnknownAlgorithmException;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.SimpleHashRequest;
import org.apache.shiro.crypto.hash.format.DefaultHashFormatFactory;
import org.apache.shiro.crypto.hash.format.HashFormat;
import org.apache.shiro.crypto.hash.format.HashFormatFactory;
import org.apache.shiro.crypto.hash.format.HexFormat;
import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat;
import org.apache.shiro.io.ResourceUtils;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.JavaEnvironment;
import org.apache.shiro.util.StringUtils;
import java.util.*;


import java.io.File;
import java.io.IOException;
import java.util.Arrays;

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
public final class Hasher {

	private static final String HEX_PREFIX = "0x";
	private static final String DEFAULT_ALGORITHM_NAME = "SHA-256";
	private static final String DEFAULT_PASSWORD_ALGORITHM_NAME = DefaultPasswordService.DEFAULT_HASH_ALGORITHM;
	private static final int DEFAULT_GENERATED_SALT_SIZE = 512;
	private static final int DEFAULT_NUM_ITERATIONS = 500000;
	private static final int DEFAULT_PASSWORD_NUM_ITERATIONS = DefaultPasswordService.DEFAULT_HASH_ITERATIONS;

	private static final Option ALGORITHM = new Option("a", "algorithm", true, "hash algorithm name.  Defaults to SHA-256 when password hashing, MD5 otherwise.");
	private static final Option DEBUG = new Option("d", "debug", false, "show additional error (stack trace) information.");
	private static final Option FORMAT = new Option("f", "format", true, "hash output format.  Defaults to 'shiro1' when password hashing, 'hex' otherwise.  See below for more information.");
	private static final Option HELP = new Option("help", "help", false, "show this help message.");
	private static final Option ITERATIONS = new Option("i", "iterations", true, "number of hash iterations.  Defaults to " + DEFAULT_PASSWORD_NUM_ITERATIONS + " when password hashing, 1 otherwise.");
	private static final Option PASSWORD = new Option("p", "password", false, "hash a password (disable typing echo)");
	private static final Option PASSWORD_NC = new Option("pnc", "pnoconfirm", false, "hash a password (disable typing echo) but disable password confirmation prompt.");
	private static final Option RESOURCE = new Option("r", "resource", false, "read and hash the resource located at <value>.  See below for more information.");
	private static final Option SALT = new Option("s", "salt", true, "use the specified salt.  <arg> is plaintext.");
	private static final Option SALT_BYTES = new Option("sb", "saltbytes", true, "use the specified salt bytes.  <arg> is hex or base64 encoded text.");
	private static final Option SALT_GEN = new Option("gs", "gensalt", false, "generate and use a random salt. Defaults to true when password hashing, false otherwise.");
	private static final Option NO_SALT_GEN = new Option("ngs", "nogensalt", false, "do NOT generate and use a random salt (valid during password hashing).");
	private static final Option SALT_GEN_SIZE = new Option("gss", "gensaltsize", true, "the number of salt bits (not bytes!) to generate.  Defaults to 128.");
	private static final Option PRIVATE_SALT = new Option("ps", "privatesalt", true, "use the specified private salt.  <arg> is plaintext.");
	private static final Option PRIVATE_SALT_BYTES = new Option("psb", "privatesaltbytes", true, "use the specified private salt bytes.  <arg> is hex or base64 encoded text.");

	private static final String SALT_MUTEX_MSG = createMutexMessage(SALT, SALT_BYTES);

	private static final HashFormatFactory HASH_FORMAT_FACTORY = new DefaultHashFormatFactory();



	public static void main(String[] args) {
		boolean debug = false;

		int iterations = 0; //0 means unspecified by the end-user
		boolean resource = false;
		boolean password = false;
		boolean passwordConfirm = true;
		String saltString = null;
		String saltBytesString = null;
		boolean generateSalt = false;
		int generatedSaltSize = DEFAULT_GENERATED_SALT_SIZE;
		String privateSaltString = null;
		String privateSaltBytesString = null;	        
		char[] passwordChars = null;
		Object source;
		Scanner sc=new Scanner(System.in);
		System.out.println("Introduce la password a Hashear");
		String pass=sc.next();
		passwordChars = readPassword(pass);
		source = passwordChars;
		String formatString = null;
		String algorithm = DEFAULT_PASSWORD_ALGORITHM_NAME;


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
		if (passwordChars != null && passwordChars.length > 0) {
            for (int i = 0; i < passwordChars.length; i++) {
                passwordChars[i] = ' ';
            }
		}
	}
	private static char[] readPassword(String pass) {

		char[] first = pass.toCharArray();
		return first;
	}
	private static ByteSource getSalt(String saltString, String saltBytesString, boolean generateSalt, int generatedSaltSize) {

		if (saltString != null) {
			if (generateSalt || (saltBytesString != null)) {
				throw new IllegalArgumentException(SALT_MUTEX_MSG);
			}
			return ByteSource.Util.bytes(saltString);
		}

		if (saltBytesString != null) {
			if (generateSalt) {
				throw new IllegalArgumentException(SALT_MUTEX_MSG);
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
			int byteSize = generatedSaltSize / 8; //generatedSaltSize is in *bits* - convert to byte size:
			return generator.nextBytes(byteSize);


		}

		//no salt used:
		return null;
	}
	private static String createMutexMessage(Option... options) {
		StringBuilder sb = new StringBuilder();
		sb.append("The ");

		for (int i = 0; i < options.length; i++) {
			if (i > 0) {
				sb.append(", ");
			}
			Option o = options[0];
			sb.append("-").append(o.getOpt()).append("/--").append(o.getLongOpt());
		}
		sb.append(" and generated salt options are mutually exclusive.  Only one of them may be used at a time");
		return sb.toString();
	}
}
