use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, PrivateKey,
    PrivateKeyChain,
};
use uuid::Uuid;

use crate::ca::Issued;

/// PKCS#12 with 3DES and SHA-1 MAC: the one combination every iOS, Android and
/// desktop keystore imports.
pub fn pkcs12(issued: &Issued, friendly_name: &str, password: &str) -> anyhow::Result<Vec<u8>> {
    let key = PrivateKey::from_der(&issued.key_pkcs8_der)?;
    let mut certs = vec![Certificate::from_der(&issued.cert_der)?];
    for der in &issued.chain_der {
        certs.push(Certificate::from_der(der)?);
    }
    let local_key_id = issued.fingerprint().into_bytes();
    let chain = PrivateKeyChain::new(local_key_id, key, certs);
    let mut store = KeyStore::new();
    store.add_entry(friendly_name, KeyStoreEntry::PrivateKeyChain(chain));
    Ok(store
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc)
        .mac_algorithm(MacAlgorithm::HmacSha1)
        .write()?)
}

/// An Apple configuration profile carrying the PKCS#12. The password is left out so
/// the device asks for it. A stable identifier per device makes a rotated profile
/// replace the previous one.
pub fn mobileconfig(device_id: Uuid, device_name: &str, p12: &[u8]) -> String {
    let name = xml_escape(device_name);
    let data = STANDARD.encode(p12);
    let profile_uuid = Uuid::new_v4();
    let payload_uuid = Uuid::new_v4();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>{name}.p12</string>
			<key>PayloadContent</key>
			<data>{data}</data>
			<key>PayloadDescription</key>
			<string>Client certificate for {name}</string>
			<key>PayloadDisplayName</key>
			<string>{name}</string>
			<key>PayloadIdentifier</key>
			<string>tegata.{device_id}.identity</string>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs12</string>
			<key>PayloadUUID</key>
			<string>{payload_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Installs the client certificate for {name}.</string>
	<key>PayloadDisplayName</key>
	<string>tegata: {name}</string>
	<key>PayloadIdentifier</key>
	<string>tegata.{device_id}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{profile_uuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{Ca, LocalCa};

    #[tokio::test]
    async fn pkcs12_round_trips() {
        let dir = std::env::temp_dir().join(format!("tegata-test-{}", Uuid::new_v4()));
        let ca = LocalCa::open(&dir, "test ca").await.unwrap();
        let issued = ca.issue("phone", time::Duration::days(30)).await.unwrap();
        let p12 = pkcs12(&issued, "phone", "abcd-efgh").unwrap();

        let store =
            KeyStore::from_pkcs12(&p12, "abcd-efgh", p12_keystore::Pkcs12ImportPolicy::default())
                .unwrap();
        let (alias, chain) = store.private_key_chain().unwrap();
        assert_eq!(alias, "phone");
        assert_eq!(chain.certs().len(), 2);
        assert_eq!(chain.key().as_der(), issued.key_pkcs8_der.as_slice());
        assert!(
            KeyStore::from_pkcs12(&p12, "wrong", p12_keystore::Pkcs12ImportPolicy::default())
                .is_err()
        );

        let profile = mobileconfig(Uuid::nil(), "a <b>", &p12);
        assert!(profile.contains("com.apple.security.pkcs12"));
        assert!(profile.contains("a &lt;b&gt;"));
        assert!(!profile.contains("abcd-efgh"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
