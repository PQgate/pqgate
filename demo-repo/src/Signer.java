import java.security.*;
public class Signer {
    KeyPairGenerator legacy() throws Exception { return KeyPairGenerator.getInstance("RSA"); }
    Signature pqc() throws Exception { return Signature.getInstance("ML-DSA-87"); }
}
