# X-Ways-VirusTotal-Extension
X-Ways Extension to look up hashes in Virus total and identify malicious files

Home of the VirusTotal extension for X-Ways that Polito Inc. developed for use with VirusTotal.

VirusTotal hash query extension for X-Ways Forensics platform. Requires VirusTotal API credentials.
VirusTotal api credentials can be obtained here : https://www.virustotal.com/gui/join-us
Please see our blog post for detailed instructions about how to use this VirusTotal plugin with X-Ways: https://www.politoinc.com/VirusTotal It has been tested on X-Ways versions 19.3 to 20.5 (64-bit only). Additional versions are still being tested for compatibility. 

Initial release (version 0.2). The plugin will require you to create a vtconfig.txt file in the same folder where the .DLL file is located. This should contain two fields separated by a colon ":" character. The first field should be your API key for VirusTotal and the second field should be the number of queries per minute that your API key allows. For example:

012345...abcdef:4

This will tell the X-Tension to use your API key that starts with 012345...abcdef at a rate of 4 queries per minute. Note: notepad.exe will add additional characters to text file that is incompatible with X-Ways.

We are not responsible for any issues you encounter related to use of your API key at a rate that is higher than what VirusTotal allows.

NOTE: using a rate of zero (0) tells the X-Tension to go as fast as possible (it will not rate-limit). If you have unlimited queries on VirusTotal this will get your results the fastest.

—

Feel free to open an issue in GitHub or contact us if you encounter any issues or want to suggest a feature. We will do our best to respond in a timely manner.


<p>Hashes of the files : 

<p>  MD5      put md5hash here                  XT_VirusTotal.dll
 Note: notepad.exe will add additional characters to text file that is incompatible with X-Ways.<p> After running plugin, output of results are in Metadata column
<p>
<!-- See blog post here for more details and instructions for how to use this extension in X-Ways: -->
<!-- <img src="https://github.com/PolitoInc/X-Ways-VirusTotal-Extension/raw/main/virustotal-xways.png"> -->
<img src="virustotal-xways.png">

<p># License
Polito Inc. is providing the VirusTotal hash query extension ("this Software") for free for the benefit of the Digital Forensics community. This Software is provided "as is", without any warranty of any kind, express or implied. You may copy, distribute, and use this Software without charge for commercial or non-commercial purposes, provided that you give full credit to its source and you do not sell, rent, or lease it and do not use it for any illegal purpose. While we are unable to provide support for this Software, feel free to contact us at  <b>info(at)politoinc.com</b>  with any bug reports or feature requests.
