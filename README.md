# X-Ways-VirusTotal-Extension
X-Ways Extension to look up hashes in Virus total and identify malicious files

Home of the VirusTotal extension for X-Ways that Polito Inc. developed for use with VirusTotal.

The use of this X-Tension will require VirusTotal API credentials.
VirusTotal API credentials can be obtained here: https://www.virustotal.com/gui/join-us

Please see our blog post for detailed instructions about how to use this VirusTotal X-Tension with X-Ways: https://www.politoinc.com/post/enhancing-digital-forensics-with-x-ways-x-tensions-virustotal-plugin 

This X-Tension has been tested on X-Ways versions 19.3 to 20.5 (64-bit only). Additional versions are still being tested for compatibility. 

The plugin will require you to create a file named vtconfig.txt in the same folder where the X-Tension .DLL file is located. This should contain two fields separated by a colon ":" character. The first field should be your API key for VirusTotal and the second field should be the number of queries per minute that your API key allows. For example:

`012345...abcdef:4`

This will tell the X-Tension to use your API key that starts with 012345...abcdef at a rate of 4 queries per minute. Note: The file needs to be saved in UTF-8 encoding; if you use UTF-16, notepad.exe will add additional characters to the text file which will cause issues when the X-Tension attempts to read the configuration file.

Polito is not responsible for any issues you encounter related to use of your API key at a rate that is higher than what VirusTotal allows.

NOTE: using a rate of zero (0) tells the X-Tension to go as fast as possible (it will not rate-limit). If you have unlimited queries on VirusTotal this will get your results the fastest.

—

Feel free to open an issue in GitHub or contact us if you encounter any issues or want to suggest a feature. We will do our best to respond in a timely manner.


<p> After running plugin, output of results are in Metadata column:<p>
<!-- See blog post here for more details and instructions for how to use this extension in X-Ways: -->
<!-- <img src="https://github.com/PolitoInc/X-Ways-VirusTotal-Extension/raw/main/virustotal-xways.png"> -->
<img src="virustotal-xways.png">

## License
Polito Inc. is providing the VirusTotal hash query extension ("this Software") for free for the benefit of the Digital Forensics community. This Software is provided "as is", without any warranty of any kind, express or implied. You may copy, distribute, and use this Software without charge for commercial or non-commercial purposes, provided that you give full credit to its source and you do not sell, rent, or lease it and do not use it for any illegal purpose. While we are unable to provide support for this Software, feel free to contact us at  <b>info(at)politoinc.com</b>  with any bug reports or feature requests.
