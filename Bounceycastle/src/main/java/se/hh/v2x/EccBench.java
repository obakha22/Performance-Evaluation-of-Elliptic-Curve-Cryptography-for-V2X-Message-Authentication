package se.hh.v2x;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 8, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(value = 2)
public class EccBench {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @State(Scope.Thread)
    public static class BenchState {
        @Param({"64", "256", "1024"})
        public int msgSize;

        @Param({"secp256r1", "brainpoolP256r1"})
        public String curve;

        public byte[] msg;
        public SecureRandom rnd;

        // ECDSA
        public KeyPair ecdsaKp;
        public Signature ecdsaSigner;
        public Signature ecdsaVerifier;
        public byte[] ecdsaSig;

        // Ed25519
        public KeyPair edKp;
        public Signature edSigner;
        public Signature edVerifier;
        public byte[] edSig;

        @Setup(Level.Trial)
        public void setupTrial() throws Exception {
            msg = new byte[msgSize];
            for (int i = 0; i < msg.length; i++) msg[i] = (byte) (i * 31); // deterministic
            rnd = new SecureRandom();

            // ECDSA keys + objects
            KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");
            ecKpg.initialize(new ECGenParameterSpec(curve), new SecureRandom());
            ecdsaKp = ecKpg.generateKeyPair();

            ecdsaSigner = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerifier = Signature.getInstance("SHA256withECDSA", "BC");

            // Precompute a valid signature for verify benchmark
            ecdsaSigner.initSign(ecdsaKp.getPrivate(), new SecureRandom());
            ecdsaSigner.update(msg);
            ecdsaSig = ecdsaSigner.sign();

            // Ed25519 keys + objects
            KeyPairGenerator edKpg = KeyPairGenerator.getInstance("Ed25519", "BC");
            edKp = edKpg.generateKeyPair();

            edSigner = Signature.getInstance("Ed25519", "BC");
            edVerifier = Signature.getInstance("Ed25519", "BC");

            edSigner.initSign(edKp.getPrivate());
            edSigner.update(msg);
            edSig = edSigner.sign();
        }
    }

    // --------- ECDSA benchmarks ---------

    @Benchmark
    public void ecdsa_sign(BenchState s, Blackhole bh) throws Exception {
        s.ecdsaSigner.initSign(s.ecdsaKp.getPrivate(), s.rnd);
        s.ecdsaSigner.update(s.msg);
        bh.consume(s.ecdsaSigner.sign());
    }

    @Benchmark
    public void ecdsa_verify(BenchState s, Blackhole bh) throws Exception {
        s.ecdsaVerifier.initVerify(s.ecdsaKp.getPublic());
        s.ecdsaVerifier.update(s.msg);
        bh.consume(s.ecdsaVerifier.verify(s.ecdsaSig));
    }

    // --------- Ed25519 benchmarks ---------

    @Benchmark
    public void ed25519_sign(BenchState s, Blackhole bh) throws Exception {
        s.edSigner.initSign(s.edKp.getPrivate());
        s.edSigner.update(s.msg);
        bh.consume(s.edSigner.sign());
    }

    @Benchmark
    public void ed25519_verify(BenchState s, Blackhole bh) throws Exception {
        s.edVerifier.initVerify(s.edKp.getPublic());
        s.edVerifier.update(s.msg);
        bh.consume(s.edVerifier.verify(s.edSig));
    }
}