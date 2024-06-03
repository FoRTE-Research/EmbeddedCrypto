MSP432, MSP430F5529 and MSP430FR5994 require adding corresponding TI Driverlib folder. 

For MSP430G2553, switch to the MSP430G2553_crypto branch, download the AES folder, and load it into Code Composer Studio.  Use the Flash button to run it on your board.

Additional Instructions: 
## Ambiq Apollo Blue 3: 

1. Store all library folders in keil folder inside your project. E.g. "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo_aes\keil\tiny_aes\"
2. In the project explorer, right click on the keil folder, select "Add existing files" and select all the individual library files to be included(e.g. test.h, experiment_time.h, aes.c, aes.h).  
3. In main.c, put absolute paths of libraries for including all the required libraries and test.h. 
e.g. #include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo_aes\keil\tiny_aes\aes.h" instead of #include "aes.h"

## Hifive 1 Rev B: 

1. Put time.h, experiment_time.h in src. 
2. In main.c, put absolute paths of libraries for including all the required libraries and test.h. 
e.g. #include "C:\Users\kuthe\wsFreedomStudio\sifive_hifive1_revb_aes\tiny_aes\aes.h". Do the same for .c files of libraries in the main.c.