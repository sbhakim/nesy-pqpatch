import java.security.Signature;

class ParamFixture {
    Signature build() throws Exception {
        String algorithm = "ML-DSA-65";
        return Signature.getInstance(algorithm);
    }
}
