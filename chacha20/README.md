MSP432, MSP430F5529 and MSP430FR5994 require adding corresponding TI Driverlib folder.  

For MSP430G2553, switch to the MSP430G2553_crypto branch, download the chacha20_v2 folder, and load it into Code Composer Studio.  Use the Flash button to run it on your board.

Additional Instructions: 
## Ambiq Apollo Blue 3: 

1. Store all library folders in keil folder inside your project. E.g. "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo3_chacha\keil\portable8439\"
2. In the project explorer, right click on the keil folder, select "Add existing files" and select all the individual library files to be included(e.g. experiment_time.h, chacha-portable.c, chacha-portable.h).  
3. In main.c, put absolute paths of libraries for including all the required libraries and test.h. 
e.g. #include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo3_chacha\keil\portable8439\chacha-portable\chacha-portable.h" instead of #include "chacha-portable.h"

## Hifive 1 Rev B: 

1. Put time.h, experiment_time.h in src. 
2. In main.c, put absolute paths of libraries for including all the required libraries and test.h. 
e.g. #include "C:\Users\kuthe\wsFreedomStudio\sifive_hifive1_revb_chacha_new\src\portable8439\chacha-portable\chacha-portable.h". Do the same for .c files of libraries in the main.c.