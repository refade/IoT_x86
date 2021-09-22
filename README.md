# IoT_x86
  Retrieval Internet of Thing for x86 Malware Analysis 

## Commercial Antivirus Limitation

Technically, the modus operandi for the identification of malicious files and servers refers to consult in named blacklist databases. The VirusTotal platform issues the diagnoses regarding malignant characteristics related to files and web servers.

When it comes to suspicious files, VirusTotal issues the diagnostics provided by the world's leading commercial antivirus products. Regarding suspicious web servers, VirusTotal uses the database responsible for sensing virtual addresses with malicious practices.

VirusTotal has Application Programming Interface (APIs) that allow programmers to query the platform in an automated way and without the use of the graphical web interface. The proposed paper employs two of the APIs made available by VirusTotal. The first one is responsible for sending the investigated files to the platform server. The second API, in turn, makes commercial antivirus diagnostics available for files submitted to the platform by the first API.

Initially, the executable malwares are sent to the server belonging to the VirusTotal platform. After that, the executables are analyzed by the 86 commercial antiviruses linked to VirusTotal. Therefore, the antivirus provides its diagnostics for the executables submitted to the platform. VirusTotal allows the possibility of issuing three different types of diagnostics: malware, benign and omission.

Then, through the VirusTotal platform, the proposed paper investigates 77 commercial antiviruses with their respective results presented in Table 2. We used 1600 malicious executables for ANDROID obtained from the REFADE database. The goal of the work is to check the number of virtual pests cataloged by antivirus. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, the larger the database of malwares blacklisted, the better it tends to be the defense provided by the antivirus.

As for the first possibility of VirusTotal, the antivirus detects the malignity of the suspicious file. In the proposed experimental environment, all submitted executables are public domain malwares. Therefore, in the proposed study, the antivirus hits when it detects the malignity of the investigated executable. Malware detection indicates that the antivirus provides a robust service against cyber-intrusions. As larger the blacklist database, better tends to be the defense provided by the antivirus.

In the second possibility, the antivirus attests to the benignity of the investigated file. Therefore, in the proposed study, when the antivirus attests the benignity of the file, it is a case of a false negative – since all the samples are malicious. That is, the investigated executable is a malware; however, the antivirus attests to benignity in the wrong way.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

Table 2 shows the results of the evaluated 86 antivirus products. Only two of these antiviruses scored above 90%. These antiviruses were: Symantec Mobile Insight and K7GW. Malware detection indicates that these antivirus programs provide an efficient service against cyber-intrusions.

A major adversity in combating malicious applications is the fact that antivirus makers do not share their malware blacklists due to commercial disputes. Through Table 2 analyse, the proposed paper points to an aggravating factor of this adversity: the same antivirus vendor does not even share its databases between its different antivirus programs. Note, for example, that McAfee and McAfee-GW-Edition antiviruses belong to the same company. Their blacklists, though robust, are not shared with each other. Therefore, the commercial strategies of the same company hinder the confrontation with malware. It complements that antivirus vendors are not necessarily concerned with avoiding cyber-invasions, but with optimizing their business income.

Malware detection ranged from 0% to 93,71%, depending on the antivirus being investigated. On average, the 77 antiviruses were able to detect 32,60% of the evaluated virtual pests, with a standard deviation of 38,43. The high standard deviation indicates that the detection of malicious executables may suffer abrupt variations depending on the antivirus chosen. It is determined that the protection, against cybernetic invasions, is due to the choice of a robust antivirus with a large and updated blacklist.

As for the false negatives, BitDefender, Baidu and Panda antiviruses, wrongly stated that malware was benign in more than 95% of cases. On average, antiviruses attested false negatives in 43,34% of the cases, with a standard deviation of 41,22. Tackling the benignity of malware can lead to irrecoverable damage. A person or institution, for example, would rely on a particular malicious application when, in fact, it is malware.

Acronis, eScan, Palo Alto Networks, Sophos AV-Sophos, SentinelOne (Static-ML), SecureAge APEX, CrowdStrike Falcon, Sangfor Engine Zero, Sophos ML and Trapmine antivirus companies have not omitted opinion on any of the 1600 samples malicious. Therefore, about 13% of antivirus softwares were not able to diagnose any of the malicious samples. On average, the antiviruses were missing in 24.06% of the cases, with a standard deviation of 41.33. The omission of the diagnosis points to the limitation of these antiviruses that have limited blacklists for detection of malware in real time.

It is included as adversity, in the combat to malicious applications, the fact of the commercial antiviruses do not possess a pattern in the classification of the malwares as seen in Table 3. We choose 3 of 1600 REWEMA malwares samples in order to exemplify the miscellaneous classifications of commercial antiviruses. The chosen malware are VirusShare_0d1b1736b6b210f5e036c35278db4fbc, VirusShare_0d2ca61588afc2c98798333dae466775 and VirusShare_0d00ec451b1aa695055f43e355442c89. In this way, the time when manufacturers react to a new virtual plague is affected dramatically. As there is no a pattern, antiviruses give the names that they want, for example, a company can identify a malware as "Malware.1" and a second company identify it as "Malware12310". Therefore, the lack of a pattern, besides the no-sharing of information among the antivirus manufacturers, hinders the fast and effective detection of a malicious application.

###### Table 2 Results of 77 commercial antiviruses:

Antivirus |	Deteccion (%) |	False Negative (%) |	Omission (%)
--------- | ------------- | ------------------ | -------------
MicroWorld-eScan	| 90,75% |	9,25% |	0% |
Ad-Aware	90,67	9,17	0,17
BitDefender	90,67	9,25	0,08
FireEye	90,25	9,33	0,42
GData	89,92	8,92	1,17
Emsisoft	89,75	10,17	0,08
NANO-Antivirus	88,5	11,5	0
Tencent	87,83	12,08	0,08
Ikarus	87,67	9,33	3
AVG	86,92	0,33	12,75
Kaspersky	86,75	12,67	0,58
MAX	86,67	13	0,33
McAfee	85,83	13,5	0,67
Microsoft	85,83	12,83	1,33
Symantec	85,75	12,42	1,83
Avast	85,58	12,17	2,25
ClamAV	85,58	13,17	1,25
ESET-NOD32	84,25	15,75	0
TrendMicro-HouseCall	83,42	16,5	0,08
SentinelOne	82,83	8,67	8,5
McAfee-GW-Edition	82,75	14,42	2,83
Sangfor	80,33	14	5,67
TrendMicro	80	18,42	1,58
Zillya	80	18,33	1,67
DrWeb	79,58	20,42	0
ALYac	79,42	9,25	11,33
Comodo	76,92	21,75	1,33
Rising	76,83	22,83	0,33
Fortinet	76,5	23,5	0
Jiangmin	74,17	11,17	14,67
Lionic	71,42	27,83	0,75
Avira	68,25	31,75	0
Cynet	68,17	31,58	0,25
Sophos	62,25	37,5	0,25
ZoneAlarm	56,58	43,17	0,25
Arcabit	56,5	43,5	0
Cyren	52,5	47,5	0
AhnLab-V3	44,67	55,33	0
Qihoo-360	38,58	61,33	0,08
Antiy-AVL	36	16,42	47,58
F-Secure	33,42	66,5	0,08
Avast-Mobile	32,25	67,75	0
BitDefenderTheta	28,08	71,33	0,58
MaxSecure	20,75	77,5	1,75
Panda	18,17	81,83	0
Yandex	17,83	82,08	0,08
CAT-QuickHeal	11	88,75	0,25
VIPRE	7,92	91,83	0,25
CMC	6,25	93,75	0
ViRobot	4,58	95,42	0
VBA32	3,75	96,17	0,08
Gridinsoft	1,17	97	1,83
F-Prot	0,33	1,83	97,83
SymantecMobileInsight	0,25	0	99,75
Bkav	0,17	99,08	0,75
CyrenCloud	0,08	0	99,92
TotalDefense	0,08	44	55,92
Zoner	0	98,67	1,33
Acronis	0	97	3
CrowdStrike	0	0,08	99,92
Invincea	0	0,08	99,92
Trustlook	0	0,17	99,83
Elastic	0	0,08	99,92
Babable	0	0,5	99,5
Malwarebytes	0	100	0
eGambit	0	3,17	96,83
K7AntiVirus	0	100	0
K7GW	0	100	0
Baidu	0	99,08	0,92
SUPERAntiSpyware	0	100	0
TACHYON	0	100	0
Kingsoft	0	97,08	2,92
Cybereason	0	0,08	99,92




###### Table 3 Miscellaneous classifications of commercial antiviruses:

Antivírus |	VirusShare_0d1b1736b6b210f5e036c35278db4fbc |	VirusShare_0d2ca61588afc2c98798333dae466775 |	VirusShare_0d00ec451b1aa695055f43e355442c89
--------- | ------------------------------------------- | ------------------------------------------- | --------------------------------------------
MicroWorld-eScan |  | | |
Ad-Aware
BitDefender
FireEye
GData
Emsisoft
NANO-Antivirus
Tencent
Ikarus
AVG
Kaspersky
MAX
McAfee
Microsoft
Symantec
Avast
ClamAV
ESET-NOD32
TrendMicro-HouseCall
SentinelOne
McAfee-GW-Edition
Sangfor
TrendMicro
Zillya
DrWeb
ALYac
Comodo
Rising
Fortinet
Jiangmin
Lionic
Avira
Cynet
Sophos
ZoneAlarm
Arcabit
Cyren
AhnLab-V3
Qihoo-360
Antiy-AVL
F-Secure
Avast-Mobile
BitDefenderTheta
MaxSecure
Panda
Yandex
CAT-QuickHeal
VIPRE
CMC
ViRobot
VBA32
Gridinsoft
F-Prot
SymantecMobileInsight
Bkav
CyrenCloud
TotalDefense
Zoner
Acronis
CrowdStrike
Invincea
Trustlook
Elastic
Babable
Malwarebytes
eGambit
K7AntiVirus
K7GW
Baidu
SUPERAntiSpyware
TACHYON
Kingsoft
Cybereason


## Materials and Methods

This paper proposes a database aiming at the classification of Android benign and malware executables. The database is referred to as REFADE. There are 1600 malicious executables, and 1600 other benign executables. Therefore, the REFADE base is suitable for learning with artificial intelligence, since both classes of executables have the same amount.

For the construction of a pattern recognition AI (artificial intelligence), the conventional method used for its training is the use of classes and counter classes of a certain filetype. The designation chosen to refer to the categories was "benign files" for serious and safe applications and "malignant files" for applications that can be a threat to the user. The malwares samples are executables files for Android (.apk). The virtual plages were extracted from databases made avaiable by enthusiastic groups about the study of malwares through the digital plataform VirusShare. It should be noted that all benign executables were submitted to VirusTotal and all were its benign attested by the main commercial antivirus worldwide. The diagnostics, provided by VirusTotal, corresponding to the benign and malware executables are available in the virtual address of the REFADE database.

The benign samples were extracted from Playstore, the official shop for Android devices. In addition, databases from others plataforms of benign apps were also used: APKmirror and APKpure. To avoid repeat the samples, were used authoral scripts coded in python. The scrip read the files downloaded and delete its copys.
