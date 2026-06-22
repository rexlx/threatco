package vendors

var CweDictionary = map[string]string{
	"CWE-20":  "Improper Input Validation",
	"CWE-22":  "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
	"CWE-78":  "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
	"CWE-79":  "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
	"CWE-89":  "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
	"CWE-94":  "Improper Control of Generation of Code ('Code Injection')",
	"CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
	"CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
	"CWE-125": "Out-of-bounds Read",
	"CWE-190": "Integer Overflow or Wraparound",
	"CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
	"CWE-269": "Improper Privilege Management",
	"CWE-276": "Incorrect Default Permissions",
	"CWE-287": "Improper Authentication",
	"CWE-295": "Improper Certificate Validation",
	"CWE-306": "Missing Authentication for Critical Function",
	"CWE-352": "Cross-Site Request Forgery (CSRF)",
	"CWE-416": "Use After Free",
	"CWE-434": "Unrestricted Upload of File with Dangerous Type",
	"CWE-502": "Deserialization of Untrusted Data",
	"CWE-522": "Insufficiently Protected Credentials (or Use of Hard-Coded Credentials)",
	"CWE-611": "Improper Restriction of XML External Entity Reference ('XXE')",
	"CWE-732": "Incorrect Permission Assignment for Critical Resource",
	"CWE-787": "Out-of-bounds Write",
	"CWE-862": "Missing Authorization",
	"CWE-863": "Incorrect Authorization",
}

func GetCweName(id string) string {
	if name, exists := CweDictionary[id]; exists {
		return name
	}
	return "Unknown Vulnerability Classification Scheme Context"
}
