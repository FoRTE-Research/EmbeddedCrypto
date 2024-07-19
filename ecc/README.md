MSP432, MSP430F5529 and MSP430FR5994 require adding corresponding TI Driverlib folder.  

In uECC.h, on line 92, include the absolute path of platform-specific.inc file for each board. 
For example: #include "C:\Users\kuthe\Documents\Arduino\AdafruitM0MetroExpress\ecc\bsd\platform-specific.inc"

In uECC.h, on line 187, include the absolute path of asm_arm.inc file for each board. 
For example: #include "C:\Users\kuthe\Documents\Arduino\AdafruitM0MetroExpress\ecc\bsd\asm_arm.inc"

In uECC.h, on line 750, include the absolute path of curve-specific.inc file for each board. 
For example: #include "C:\Users\kuthe\Documents\Arduino\AdafruitM0MetroExpress\ecc\bsd\curve-specific.inc"

Additional Instructions: 
## Ambiq Apollo Blue 3: 

1. Store all library folders in keil folder inside your project. E.g. "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo3_ecc\keil\tiny_ecc\"
2. In the project explorer, right click on the keil folder, select "Add existing files" and select all the individual library files to be included(e.g. experiment_time.h, curve.h, ecdh.c, ecdh.h).  
3. In main.c, put absolute paths of libraries for including all the required libraries.
e.g. #include "D:\AmbiqSuiteSDK-master\boards\apollo3_evb\examples\apollo3_ecc\keil\tiny_ecc\ecdh.h" instead of #include "ecdh.h"

## Hifive 1 Rev B: 

1. Put curve.h, experiment_time.h outside src. 
2. In main.c, put absolute paths of libraries for including all the required libraries and test.h. 
e.g. #include "C:\Users\kuthe\wsFreedomStudio\sifive_hifive1_revb_ecc_new\src\tiny_ecc\ecdh.h". Do the same for .c files of libraries in the main.c.
