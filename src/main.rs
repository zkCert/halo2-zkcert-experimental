// use halo2_base::{
//     AssignedValue,
//     utils::PrimeField, 
//     gates::{
//         GateInstructions,
//         range::{RangeConfig, RangeStrategy}
//     },
//     halo2_proofs::{
//         plonk::{Circuit, ConstraintSystem, Error}, 
//         circuit::{SimpleFloorPlanner, Layouter, Value},
//         halo2curves::bn256::Fr,
//         dev::MockProver
//     }, 
//     SKIP_FIRST_PASS
// };
// use halo2_rsa::{
//     RSAConfig,
//     RSAPubE,
//     RSAPublicKey, 
//     RSASignature,
//     RSAInstructions,
//     BigUintConfig,
//     big_uint::decompose_biguint
// };
// use num_bigint::BigUint;
// use std::str::FromStr;

// struct CertificateVerificationCircuit<F: PrimeField> {
//     _f: std::marker::PhantomData<F>,
// }

// impl<F: PrimeField> CertificateVerificationCircuit<F> {
//     const BITS_LEN:usize = 2048;
//     const LIMB_BITS:usize = 64;
//     const EXP_LIMB_BITS:usize = 5;
//     const DEFAULT_E: u128 = 65537;
//     const NUM_ADVICE:usize = 50;
//     const NUM_FIXED:usize = 1;
//     const NUM_LOOKUP_ADVICE:usize = 4;
//     const LOOKUP_BITS:usize = 12;
// }

// const DEGREE: usize = 13;

// impl<F: PrimeField> Circuit<F> for CertificateVerificationCircuit<F> {
//     type Config = RSAConfig<F>;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         unimplemented!();
//     }

//     fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//         let range_config = RangeConfig::configure(
//             meta, RangeStrategy::Vertical, 
//             &[Self::NUM_ADVICE], 
//             &[Self::NUM_LOOKUP_ADVICE], 
//             Self::NUM_FIXED, 
//             Self::LOOKUP_BITS, 
//             0, 
//             DEGREE  // Degree set to 13
//         );
//         let biguint_config = BigUintConfig::construct(range_config, Self::LIMB_BITS);
//         RSAConfig::construct(biguint_config, Self::BITS_LEN, Self::EXP_LIMB_BITS)
//     }

//     fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
//         config.range().load_lookup_table(& mut layouter)?;
//         let mut first_pass = SKIP_FIRST_PASS;
//         layouter.assign_region(
//             || "certificat chain verifier", 
//             |region| {
//                 if first_pass {
//                     first_pass = false;
//                     return Ok(());
//                 }

//                 let mut aux = config.new_context(region);
//                 let ctx = &mut aux;
//                 let e_fix = RSAPubE::Fix(BigUint::from(Self::DEFAULT_E));
                
//                 // Verify Cert 3
//                 let n_big = BigUint::from_str("25072256773181016646718001929649043437172284752110978827451245341673758518265515824620220750921274366810682997655063764396189586208088373151418554667794497434288488985609147281128841322360351415965542849416626264753334809490058670348969746086550826240466231366937756571002586959049028931911717491153543215680439438869310635579672748993762509151669079269470324005482758681846289579362736138374741810539170313375320254563526825071320753564974728585034652850725343743405185445846611159584133428989207258736588038858395777213215195426888432989580649629247513901205854186589801893897065580902313724004472501504861753897483").unwrap();
//                 let public_key = RSAPublicKey::new(Value::known(n_big), e_fix);     // might be buggy
//                 let public_key = config.assign_public_key(ctx, public_key)?;

//                 let sign_big = BigUint::from_str("20680993081803492142822962338302702090012972524732502784594581432470613813233541192524722764024920354503190154965692204093222747459365939459424002291455821362931301367726976136689527902609981789422816403441812993066615945663080866662123305222197163642780263995683496902379311723788215176139030235483965841222112599769895713361498037517850307320304159522325294215159771451146358568063624507935867246474696795928738358732497200607481490371297698548140240747180387324746875549163061769304144127629403810621772482130341993919561021750878201129002779865697405289828440208414276640613469910559702285689184938862843121612084").unwrap();
//                 let signature = RSASignature::new(Value::known(sign_big));
//                 let signature = config.assign_signature(ctx, signature)?;

//                 let hashed_msg_big = BigUint::from_str("39555517759254702188097508881010450241261293572934142180155863931106820219626").unwrap();
//                 let hashed_msg_limbs = decompose_biguint::<F>(&hashed_msg_big, 4, 256/4);
//                 let hashed_msg_assigned = hashed_msg_limbs.into_iter().map(
//                     |limb| config.gate().load_witness(ctx, Value::known(limb))
//                 ).collect::<Vec<AssignedValue<F>>>();


//                 let is_valid = config.verify_pkcs1v15_signature(ctx, &public_key, &hashed_msg_assigned, &signature)?;
//                 config.gate().assert_is_const(ctx, &is_valid, F::one());
//                 config.range().finalize(ctx);
//                 {
//                     println!("total advice cells: {}", ctx.total_advice);
//                     let const_rows = ctx.total_fixed + 1;
//                     println!("maximum rows used by a fixed column: {const_rows}");
//                     println!("lookup cells used: {}", ctx.cells_to_lookup.len());
//                 }                
//                 Ok(())
//             },
//         )?;
        
//         Ok(())

//     }

// }


// fn main() {
//     let circuit = CertificateVerificationCircuit::<Fr> {
//         _f: std::marker::PhantomData,
//     };
//     let public_inputs = vec![];
//     let k = 13;
//     let prover = match MockProver::run(k, &circuit, public_inputs) {
//         Ok(prover) => prover,
//         Err(e) => panic!("{:?}", e),
//     };
//     assert_eq!(prover.verify(), Ok(()));
// }

fn main () {
    println!("Hello World!");
}