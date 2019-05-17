package net.codejava.javaee;
import org.apache.shiro.crypto.hash.Sha256Hash;

public class pruebaHash{
	public static void main(String[] args) {
		Sha256Hash sha256Hash = new Sha256Hash("123qwe");
		System.out.println(sha256Hash.toHex());
	}
}