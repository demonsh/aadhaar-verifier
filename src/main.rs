use num_bigint::BigInt;
use std::str::FromStr;
use std::io::prelude::*;
use flate2::read::ZlibDecoder;
use chrono::NaiveDateTime;
use base64::{Engine as _, engine::general_purpose};
use hex;

// Previous struct definitions remain the same...
#[derive(Debug)]
struct Address {
    care_of: String,
    district: String,
    landmark: String,
    house: String,
    location: String,
    pincode: String,
    post_office: String,
    state: String,
    street: String,
    sub_district: String,
    vtc: String,
}

#[derive(Debug)]
struct AadhaarData {
    email_mobile_indicator: u8,
    reference_id: String,
    name: String,
    date_of_birth: String,
    gender: char,
    address: Address,
    mobile_last_digits: String,
    photo: Vec<u8>,
    signature: Vec<u8>,
}

impl AadhaarData {
    fn photo_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.photo)
    }

    fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }
}

// Previous QRParser implementation remains the same...
struct QRParser {
    uncompressed_data: Vec<u8>
}

impl QRParser {
    fn new(data: BigInt) -> Result<Self, String> {
        let bytes = data.to_bytes_be().1;
        let mut decoder = ZlibDecoder::new(&bytes[..]);
        let mut uncompressed_data = Vec::new();

        decoder.read_to_end(&mut uncompressed_data)
            .map_err(|e| format!("Failed to decompress data: {}", e))?;

        Ok(QRParser { uncompressed_data })
    }

    fn verify_version(&self) -> Result<(), String> {
        let version = &self.uncompressed_data[0..2];
        if version != [86, 50] { // "V2" in ASCII
            return Err("Invalid QR code version. Expected V2".to_string());
        }
        Ok(())
    }

    fn find_delimiters(&self) -> Vec<usize> {
        let mut delimiters = Vec::new();
        for (i, &byte) in self.uncompressed_data.iter().enumerate() {
            if byte == 255 {
                delimiters.push(i);
                if delimiters.len() == 18 { // We need 18 delimiters for V2
                    break;
                }
            }
        }
        delimiters
    }

    fn extract_field(&self, start: usize, end: usize) -> Result<String, String> {
        String::from_utf8(self.uncompressed_data[start..end].to_vec())
            .map_err(|e| format!("Failed to decode field as UTF-8: {}", e))
    }

    fn parse_aadhaar_data(&self) -> Result<AadhaarData, String> {
        self.verify_version()?;
        let delimiters = self.find_delimiters();
        if delimiters.len() != 18 {
            return Err(format!("Expected 18 delimiters, found {}", delimiters.len()));
        }

        let mut fields: Vec<String> = Vec::new();
        let mut prev = 0;
        for &d in &delimiters {
            if prev > 0 { // Skip first field (version)
                fields.push(self.extract_field(prev + 1, d)?);
            }
            prev = d;
        }

        // Extract photo data (from last delimiter to signature)
        let photo_start = delimiters[17] + 1;
        let photo_end = self.uncompressed_data.len() - 256;
        let photo = self.uncompressed_data[photo_start..photo_end].to_vec();

        // Extract signature (last 256 bytes)
        let signature = self.uncompressed_data[photo_end..].to_vec();

        Ok(AadhaarData {
            email_mobile_indicator: fields[0].parse::<u8>().map_err(|e| e.to_string())?,
            reference_id: fields[1].clone(),
            name: fields[2].clone(),
            date_of_birth: fields[3].clone(),
            gender: fields[4].chars().next().ok_or("Empty gender field")?,
            address: Address {
                care_of: fields[5].clone(),
                district: fields[6].clone(),
                landmark: fields[7].clone(),
                house: fields[8].clone(),
                location: fields[9].clone(),
                pincode: fields[10].clone(),
                post_office: fields[11].clone(),
                state: fields[12].clone(),
                street: fields[13].clone(),
                sub_district: fields[14].clone(),
                vtc: fields[15].clone(),
            },
            mobile_last_digits: fields[16].clone(),
            photo,
            signature,
        })
    }
}

fn main() {
    let test_data = "8259163575998395410294216884136380576185817320339145460288951755287582961380611852552428987321584902318624273479337130653734982789439199350807739714406680256506601030028361685736660257517232716829232450159251789263870750283214820475102793105777087762238893090228084052270739203426767272062178826235941508196284529472654271516164224874687419158221021213944829682919423174703783469927383220474654008065915029614141226522064062660593170425792840873655513538373377850112144063189928583588899889878172757870400281696669604010659786496608127700010264443115263361656744433002559396889060190428705316366290450741550935385486607346514118464415324976934593027192262025619948063647667007927187736245772179085671658409804311603784752615097922989017361163561315974008304022542448394278143245816470881130080719485003834016131185071765229491892891069788319670287394271744730364788949609836924781874523936880888005883165757273872375006288978183466996520618718348187182821516617721340861010989807614756396013627238651856164981477576514065364628430139194213240602981419233621531616776712580234318576148789862972873366521755587675635811636464535551028275057950562020714225333126426609311459495088802145911084644641596208432517247324679678535859879970296810837735288916946197174410518342751033634782712968162882714769666441813893046220965525694847349131353986974388432968669605721975441870936552792275255624723251162192468002453471184713983574359601113515796454264270501379717344206777921353459767049560942843350534472442799601294637063232419543855742825887931841338302499933012059977947394755335155868283405337181095220998277373266658634859632929226320059674299759100792654417315629048732480315019941928105082550091217622422743467170706956093632228513797781797454779203616427853022505097310749994766657051986303478622173767936568165644251615127773430128638507677775244195799780291921828512257290767451475181728141544788756907393883042588060697683541401090581157249784874529424005078918452607589129440476242749110421616270676359722523229311894327359615548588038186027827017569331332262329182564217789843145105509621002324556840213928256545454178891208004109769624959566302976213521762873815749009289995208912424872527724417047936432945498377307452190302923489092664437908497749093491199476080757200233878726847198496754472664256996743796092233459542884818717466621372105594672115988382565552756801323160697003960485232732393383241422077506009076922303757067128564302338914230360252223406874457414109774901980252709597099278192874164252010830754720603092419792069707099362278082792090307065378744856387301364608460967253691290230861162587170799141457093188189022390589265654613500974699477990974878105678883229707694455342266695530373994049224098435972125150350136428446936271698977517627416435999970351222450833295217051468307037908262231982382247410542334757724852032521780157518474618653527191342825230455100778913195115477763082159513429761573752871477695723697689470263993132596482716347199834315782099668846081963760553679915994617396376870314998926788197388410764535427795200340714967872713095483294486407886767431404892448155562283436571050452251042117926586451385682519188252281397";

    match BigInt::from_str(test_data) {
        Ok(big_num) => {
            match QRParser::new(big_num) {
                Ok(parser) => {
                    match parser.parse_aadhaar_data() {
                        Ok(aadhaar_data) => {
                            println!("Aadhaar Data:");
                            println!("Name: {}", aadhaar_data.name);
                            println!("Gender: {}", aadhaar_data.gender);
                            println!("Date of Birth: {}", aadhaar_data.date_of_birth);
                            println!("Reference ID: {}", aadhaar_data.reference_id);
                            println!("Mobile Last Digits: {}", aadhaar_data.mobile_last_digits);
                            println!("\nAddress:");
                            println!("  House: {}", aadhaar_data.address.house);
                            println!("  Street: {}", aadhaar_data.address.street);
                            println!("  Landmark: {}", aadhaar_data.address.landmark);
                            println!("  Locality: {}", aadhaar_data.address.location);
                            println!("  District: {}", aadhaar_data.address.district);
                            println!("  State: {}", aadhaar_data.address.state);
                            println!("  Pincode: {}", aadhaar_data.address.pincode);

                            println!("\nPhoto (Base64):\n{}", aadhaar_data.photo_base64());
                            println!("\nSignature (Hex):\n{}", aadhaar_data.signature_hex());
                        },
                        Err(e) => println!("Error parsing Aadhaar data: {}", e)
                    }
                },
                Err(e) => println!("Error creating parser: {}", e)
            }
        },
        Err(e) => println!("Error parsing big integer: {}", e)
    }
}