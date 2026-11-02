//! The instance's voicemail spool (`var/spool/asterisk/voicemail`):
//! reading the messages app_voicemail saved, and writing hand-made ones.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use bstr::ByteSlice;
use regex::Regex;

/// One message: its spool folder, its number, and the fields of its
/// `msgNNNN.txt`.
#[derive(Clone, Debug)]
pub struct Msg {
    /// The folder it is in (`INBOX`, `Old`, `Urgent`, ...).
    pub folder: String,
    /// Its number (`msg0003` is 3).
    pub number: u32,
    /// The `key=value` lines (text that is not UTF-8 is replaced).
    pub fields: HashMap<String, String>,
}

impl Msg {
    /// A field (empty when absent).
    pub fn get(&self, key: &str) -> &str {
        self.fields.get(key).map(String::as_str).unwrap_or_default()
    }

    /// Whether the message has the field.
    pub fn has(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// The `msg_id` field.
    pub fn msg_id(&self) -> String {
        self.get("msg_id").to_string()
    }
}

/// The `key=value` lines of a message file (comment lines skipped).
fn read_txt(path: &Path) -> Result<HashMap<String, String>> {
    let data = std::fs::read(path).with_context(|| path.display().to_string())?;
    let mut fields = HashMap::new();
    for line in data.lines() {
        if line.starts_with(b";") {
            continue;
        }
        if let Some(i) = line.find_byte(b'=') {
            fields.insert(
                line[..i].to_str_lossy().into_owned(),
                line[i + 1..].to_str_lossy().into_owned(),
            );
        }
    }
    Ok(fields)
}

/// The voicemail spool of an instance.
#[derive(Clone, Debug)]
pub struct Spool {
    /// `<instance>/var/spool/asterisk/voicemail`.
    pub dir: PathBuf,
}

impl Spool {
    /// The spool in `dir`.
    pub fn new(dir: PathBuf) -> Spool {
        Spool { dir }
    }

    /// The messages of a mailbox (`"default/1001"`) by folder, each folder
    /// in file name order.
    pub fn read(&self, mbox: &str) -> BTreeMap<String, Vec<Msg>> {
        let re = Regex::new(r"^msg(\d+)\.txt$").expect("regex");
        let mut res: BTreeMap<String, Vec<(String, Msg)>> = BTreeMap::new();
        let Ok(folders) = std::fs::read_dir(self.dir.join(mbox)) else {
            return BTreeMap::new();
        };
        for f in folders.flatten() {
            let folder = f.file_name().to_string_lossy().into_owned();
            if folder.starts_with('.') {
                continue;
            }
            let Ok(files) = std::fs::read_dir(f.path()) else {
                continue;
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                let Some(num) = re.captures(&name).and_then(|c| c[1].parse().ok()) else {
                    continue;
                };
                // A message being written may vanish under us.
                let Ok(fields) = read_txt(&file.path()) else {
                    continue;
                };
                res.entry(folder.clone()).or_default().push((
                    name,
                    Msg {
                        folder: folder.clone(),
                        number: num,
                        fields,
                    },
                ));
            }
        }
        res.into_iter()
            .map(|(folder, mut msgs)| {
                msgs.sort_by(|a, b| a.0.cmp(&b.0));
                (folder, msgs.into_iter().map(|(_, m)| m).collect())
            })
            .collect()
    }

    /// The `msg_id`s of a mailbox by folder.
    pub fn ids(&self, mbox: &str) -> BTreeMap<String, Vec<String>> {
        self.read(mbox)
            .into_iter()
            .map(|(f, msgs)| (f, msgs.iter().map(Msg::msg_id).collect()))
            .collect()
    }

    /// The `msg_id`s of one folder of a mailbox (none when it is empty).
    pub fn folder_ids(&self, mbox: &str, folder: &str) -> Vec<String> {
        self.ids(mbox).remove(folder).unwrap_or_default()
    }

    /// Every message of a mailbox.
    pub fn all(&self, mbox: &str) -> Vec<Msg> {
        self.read(mbox).into_values().flatten().collect()
    }

    /// Removes a mailbox or one of its folders (`"default/1001/Cust2"`).
    pub fn remove(&self, path: &str) {
        let _ = std::fs::remove_dir_all(self.dir.join(path));
    }

    /// Writes a hand-made message `msgNNNN` into a folder of a mailbox; its
    /// sound is a copy of the first message of `default/1001`.
    #[allow(clippy::too_many_arguments)]
    pub fn craft(
        &self,
        mbox: &str,
        folder: &str,
        num: u32,
        msg_id: &str,
        callerid: &[u8],
        origtime: u64,
        origdate: &str,
    ) -> Result<()> {
        let d = self.dir.join(mbox).join(folder);
        std::fs::create_dir_all(&d)?;
        let wav = self.first_wav("default/1001")?;
        std::fs::copy(&wav, d.join(format!("msg{num:04}.wav")))?;
        let mut txt = b";\n; Message Information file\n;\n[message]\norigmailbox=1001\ncontext=dpma-vm-leave\n\
exten=1001\nrdnis=unknown\npriority=1\ncallerchan=Local/1001@dpma-vm-leave-0;2\n"
            .to_vec();
        txt.extend_from_slice(b"callerid=");
        txt.extend_from_slice(callerid);
        txt.push(b'\n');
        txt.extend_from_slice(
            format!(
                "origdate={origdate}\norigtime={origtime}\ncategory=\nmsg_id={msg_id}\nflag=\nduration=2\n"
            )
            .as_bytes(),
        );
        let path = d.join(format!("msg{num:04}.txt"));
        std::fs::write(&path, txt).with_context(|| path.display().to_string())
    }

    /// Writes message `msgNNNN` into a folder of a mailbox as a copy of
    /// message `src` of mailbox `src_mbox` (its sound, and its
    /// `msgNNNN.txt` with the values of `fields` replaced).
    pub fn copy_msg(
        &self,
        src_mbox: &str,
        src: &Msg,
        mbox: &str,
        folder: &str,
        num: u32,
        fields: &[(&str, &[u8])],
    ) -> Result<()> {
        let from = self
            .dir
            .join(src_mbox)
            .join(&src.folder)
            .join(format!("msg{:04}", src.number));
        let d = self.dir.join(mbox).join(folder);
        std::fs::create_dir_all(&d)?;
        let to = d.join(format!("msg{num:04}"));
        std::fs::copy(from.with_extension("wav"), to.with_extension("wav"))?;
        let txt = std::fs::read(from.with_extension("txt"))?;
        let mut out = Vec::new();
        let mut done = Vec::new();
        for line in txt.lines_with_terminator() {
            let field = fields.iter().find(|(k, _)| {
                line.strip_prefix(k.as_bytes())
                    .is_some_and(|rest| rest.starts_with(b"="))
            });
            match field {
                Some((k, v)) => {
                    out.extend_from_slice(format!("{k}=").as_bytes());
                    out.extend_from_slice(v);
                    out.push(b'\n');
                    done.push(*k);
                }
                None => out.extend_from_slice(line),
            }
        }
        if let Some((k, _)) = fields.iter().find(|(k, _)| !done.contains(k)) {
            return Err(anyhow!("no {k} in {}", from.display()));
        }
        let path = to.with_extension("txt");
        std::fs::write(&path, out).with_context(|| path.display().to_string())
    }

    /// The first `msg*.wav` of a mailbox (by path).
    fn first_wav(&self, mbox: &str) -> Result<PathBuf> {
        let mut wavs = Vec::new();
        for f in std::fs::read_dir(self.dir.join(mbox))?.flatten() {
            let Ok(files) = std::fs::read_dir(f.path()) else {
                continue;
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                if name.starts_with("msg") && name.ends_with(".wav") {
                    wavs.push(file.path());
                }
            }
        }
        wavs.sort();
        wavs.into_iter()
            .next()
            .ok_or_else(|| anyhow!("no message sound in {mbox}"))
    }
}
