package net.codejava.javaee;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.crypto.hash.SimpleHash;

public class Sha256Hash
  extends SimpleHash
{
  public static final String ALGORITHM_NAME = "SHA-256";
  
  public Sha256Hash()
  {
    super("SHA-256");
  }
  
  public Sha256Hash(Object source)
  {
    super("SHA-256", source);
  }
  
  public Sha256Hash(Object source, Object salt)
  {
    super("SHA-256", source, salt);
  }
  
  public Sha256Hash(Object source, Object salt, int hashIterations)
  {
    super("SHA-256", source, salt, hashIterations);
  }
  
  public static Sha256Hash fromHexString(String hex)
  {
    Sha256Hash hash = new Sha256Hash();
    hash.setBytes(Hex.decode(hex));
    return hash;
  }
  
  public static Sha256Hash fromBase64String(String base64)
  {
    Sha256Hash hash = new Sha256Hash();
    hash.setBytes(Base64.decode(base64));
    return hash;
  }
}