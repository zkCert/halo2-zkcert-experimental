use halo2_base::{
    AssignedValue,
    QuantumCell,
    utils::PrimeField, 
    gates::{
        GateInstructions,
        range::{RangeConfig, RangeStrategy}
    },
    halo2_proofs::{
        plonk::{Circuit, ConstraintSystem, Error, Column, Instance}, 
        circuit::{SimpleFloorPlanner, Layouter, Value, Cell, Region},
        halo2curves::{bn256::Fr},
        dev::MockProver
    }, 
    SKIP_FIRST_PASS
};
use halo2_dynamic_sha256::Sha256DynamicConfig;
use halo2_rsa::{
    RSAConfig,
    RSAPubE,
    RSAPublicKey, 
    RSASignature,
    RSAInstructions,
    RSASignatureVerifier,
    BigUintConfig,
    big_uint::decompose_biguint,
    BigUintInstructions
};
use num_bigint::BigUint;

struct CertificateVerificationCircuit<F: PrimeField> {
    n_big: BigUint,
    sign_big: BigUint,
    msg: Vec<u8>,
    _f: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CertificateVerificationCircuit<F> {
    const BITS_LEN:usize = 2048;
    const LIMB_BITS:usize = 64;
    const EXP_LIMB_BITS:usize = 5;
    const DEFAULT_E: u128 = 65537;
    const NUM_ADVICE:usize = 40;
    const NUM_FIXED:usize = 1;
    const NUM_LOOKUP_ADVICE:usize = 4;
    const LOOKUP_BITS:usize = 12;

    const MSG_LEN: usize = 1280;
    const SHA256_LOOKUP_BITS: usize = 8;        // is this enough?
    const SHA256_LOOKUP_ADVICE: usize = 8;      // might need to increase this   
}

const DEGREE: usize = 16;


#[derive(Debug,Clone)]
struct CertificateVerificationConfig<F: PrimeField> {
    rsa_config: RSAConfig<F>,
    sha256_config: Sha256DynamicConfig<F>,
    n_instance: Column<Instance>,
    hash_instance: Column<Instance>
}


impl<F: PrimeField> Circuit<F> for CertificateVerificationCircuit<F> {
    type Config = CertificateVerificationConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range_config = RangeConfig::configure(
            meta, RangeStrategy::Vertical, 
            &[Self::NUM_ADVICE], 
            &[Self::NUM_LOOKUP_ADVICE], 
            Self::NUM_FIXED, 
            Self::LOOKUP_BITS, 
            0, 
            DEGREE  // Degree set to 13
        );
        let biguint_config = BigUintConfig::construct(range_config.clone(), Self::LIMB_BITS);
        let rsa_config = RSAConfig::construct(
            biguint_config, 
            Self::BITS_LEN, 
            Self::EXP_LIMB_BITS
        );
        let sha256_config = Sha256DynamicConfig::configure(
            meta, 
            vec![Self::MSG_LEN], 
            range_config, 
            Self::SHA256_LOOKUP_BITS, 
            Self::SHA256_LOOKUP_ADVICE, 
            true
        );
        let n_instance = meta.instance_column();
        let hash_instance = meta.instance_column();
        meta.enable_equality(n_instance);   
        meta.enable_equality(hash_instance);

        Self::Config {
            rsa_config,
            sha256_config,
            n_instance,
            hash_instance
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let biguint_config = config.rsa_config.biguint_config();
        config.sha256_config.load(&mut layouter)?;
        biguint_config.range().load_lookup_table(& mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;        
        let (public_key_cells, hashed_msg_cells) = layouter.assign_region(
            || "certificat chain verifier", 
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok((vec![], vec![]));
                }
    
                let mut aux = biguint_config.new_context(region);
                let ctx = &mut aux;
                let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                
                // Verify Cert
                let public_key = RSAPublicKey::new(Value::known(self.n_big.clone()), e_fix);     // cloning might be slow
                let public_key = config.rsa_config.assign_public_key(ctx, public_key)?;
    
                let signature = RSASignature::new(Value::known(self.sign_big.clone()));             // cloning might be slow
                let signature = config.rsa_config.assign_signature(ctx, signature)?;
    
                let mut verifier = RSASignatureVerifier::new(
                    config.rsa_config.clone(),
                    config.sha256_config.clone()
                );
    
                let (is_valid, hashed_msg) = verifier.verify_pkcs1v15_signature(ctx, &public_key, &self.msg, &signature)?;
                biguint_config.gate().assert_is_const(ctx, &is_valid, F::one());
                biguint_config.range().finalize(ctx);
                {
                    println!("total advice cells: {}", ctx.total_advice);
                    let const_rows = ctx.total_fixed + 1;
                    println!("maximum rows used by a fixed column: {const_rows}");
                    println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                }                
                let public_key_cells = public_key
                    .n
                    .limbs()
                    .into_iter()
                    .map(|v| v.cell())
                    .collect::<Vec<Cell>>();
                let hashed_msg_cells = hashed_msg
                    .into_iter()
                    .map(|v| v.cell())
                    .collect::<Vec<Cell>>();
                
                Ok((public_key_cells, hashed_msg_cells))
            },
        )?;
        for (i, cell) in public_key_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.n_instance, i)?;
        }
        for (i, cell) in hashed_msg_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.hash_instance, i)?;
        }
        Ok(())

    } 
}


#[cfg(test)]
mod test {
    use super::*;
    use std::fs::File;
    use std::str::FromStr;
    use std::io::Read;
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::certificate::X509Certificate;
    use x509_parser::public_key::PublicKey;
    use sha2::{Digest, Sha256};

    pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let issuer_public_key = issuer.public_key();
        cert.verify_signature(Some(&issuer_public_key)).is_ok()
    }

    macro_rules! impl_individual_cert_verification_test_circuit {
        ($verify_cert_path:expr, $issuer_cert_path: expr, $should_err: expr) => {
            // Read the PEM certificate from a file
            let mut cert_file = File::open($verify_cert_path).expect("Failed to open PEM file");
            let mut cert_pem_buffer = Vec::new();
            cert_file.read_to_end(&mut cert_pem_buffer).expect("Failed to read PEM file");

            // Parse the PEM certificate using x509-parser
            let cert_pem = parse_x509_pem(&cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
            let cert = cert_pem.parse_x509().expect("Failed to parse PEM certificate");

            // Extract the TBS (To-Be-Signed) data from the certificate 3
            let tbs = &cert.tbs_certificate.as_ref();
            // println!("TBS (To-Be-Signed): {:x?}", tbs);

            // Extract the signature from cert 3
            let signature_bytes = &cert.signature_value;
            let signature_bigint = BigUint::from_bytes_be(&signature_bytes.data);
            // println!("Signature: {:?}", signature_bigint);

            let mut issuer_cert_file = File::open($issuer_cert_path).expect("Failed to open cert 2PEM file");
            let mut issuer_cert_pem_buffer = Vec::new();
            issuer_cert_file.read_to_end(&mut issuer_cert_pem_buffer).expect("Failed to read cert 2 PEM file");

            // Parse the PEM certificate using x509-parser
            let issuer_cert_pem = parse_x509_pem(&issuer_cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
            let issuer_cert = issuer_cert_pem.parse_x509().expect("Failed to parse PEM certificate");
            
            // Extract the public key of cert 2
            let public_key_modulus = match issuer_cert.public_key().parsed().unwrap() {
                PublicKey::RSA(pub_key) => {
                    let modulus = BigUint::from_bytes_be(pub_key.modulus);
                    // println!("Public Key modulus: {:?}", modulus);
                    modulus
                },
                _ => panic!("Failed to grab modulus. Not RSA")
            };

            // // Verify Cert3 in Rust
            // let is_valid = check_signature(&cert, &issuer_cert);

            // Verify using circuit
            let circuit = CertificateVerificationCircuit::<Fr> {
                n_big: public_key_modulus.clone(),
                sign_big: signature_bigint,
                msg: tbs.to_vec(),
                _f: std::marker::PhantomData,
            };
            
            let hashed_msg = Sha256::digest(&tbs);
            let num_limbs = 2048 / 64;
            let limb_bits = 64;
            let n_fes = decompose_biguint::<Fr>(&public_key_modulus, num_limbs, limb_bits);
            
            let hash_fes = hashed_msg.iter().map(|byte| Fr::from(*byte as u64)).collect::<Vec<Fr>>();
            let public_inputs = vec![n_fes,hash_fes];
            
            let k = DEGREE as u32;

            let prover = match MockProver::run(k, &circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:?}", e),
            };

            if $should_err {
                assert!(prover.verify().is_err());
            } else {
                assert_eq!(prover.verify(), Ok(()));
            }
        };
    }
    
    #[test]
    fn test_individual_certificate_verification2() {
        impl_individual_cert_verification_test_circuit!(
            "./certs/cert_3.pem",
            "./certs/cert_2.pem",
            false
        );
    }

    #[test]
    fn test_individual_certificate_verification3() {
        impl_individual_cert_verification_test_circuit!(
            "./certs/cert_2.pem",
            "./certs/cert_1.pem",
            false
        );
    }


    #[test]
    fn test_individual_certificate_verification4() {
        impl_individual_cert_verification_test_circuit!(
            "./certs/cert_3.pem",
            "./certs/cert_1.pem",
            true
        );
    }
}

