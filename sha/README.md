MSP432, MSP430F5529 and MSP430FR5994 require adding corresponding TI Driverlib folder.

Additional Instructions: 
## Ambiq Apollo Blue 3: 

1. Store all library folders in keil folder inside your project. E.g. "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo_aes\keil\gladman\"
2. In the project explorer, right click on the keil folder, select "Add existing files" and select all the individual library files to be included(e.g. experiment_time.h, sha2.c, sha2.h, brg_endian.h, brg_types.h).  
3. In main.c, put absolute paths of libraries for including all the required libraries. 
e.g. #include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo3_sha\keil\gladman\sha2.h" instead of #include "sha2.h"

## Hifive 1 Rev B: 

1. Put experiment_time.h in src. 
2. In main.c, put absolute paths of libraries for including all the required libraries. 
e.g. #include "C:\Users\kuthe\wsFreedomStudio\sifive_hifive1_revb_sha\gladman\sha2.h". Do the same for .c files of libraries in the main.c.