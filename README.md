# JavaCard ePurse
This is an implementation of a JavaCard ePurse.
It is based on the template shared created by [FractalizeR](https://github.com/FractalizeR/IntelliJ-IDEA-Java-Card-Project-Template)!

The project makes use of the Javacard Development Kit 2.2.1.
Building is done using an Ant build script.

# Prerequisites
* Java Runtime Environment (JRE) and the Java Development Kit (JDK).
* GlobalPlatformPro (version `v0.3.4-29-g15d7427`), for accessing the applets on the JavaCard.

# Project Setup
1. Install latest Java SDK.

2. Open project using IDEA’s `File -> Open project`

3. Go to `File -> Project Structure -> SDKs` and add the SDK you installed in step 1. If there is already something, you can delete it before adding the newly installed SDK.

4. Go to `File -> Project Structure -> Libraries`. Remove current Classes entry. Then add `\lib\jc221\lib\api.jar`.

5. Open `Common.properties` file and setup everything you need there according to the comments. This includes the __path__ to SDK installation folder. 
Open `build.xml` (this is an Ant build package so you need Ant plugin to be installed in IDEA) and correct the entries that follow `${APPLETAIDPREFIX}` to suit your AID.

6. To build the applet, go to use `View -> Tool Windows -> Ant Build`. A window will pop up on the right side of your screen. 
If you don't see any build targets, click on the green plus and select the `build.xml` file.  Use `binarize.all.standard` to build the applet for Gemalto TOPs and similiar.

7. Target files will be placed in `\out\ePurse\javacard`

8. If you have more than one applet in the project, edit `build.xml` and add a second entry under each tag with the info you need.

Now you can build your applet using IDEA's menu: `Build -> Build Project` 


## Common Problems

__Q__: IntelliJ does not autocomplete on the `.jar` I imported 

__A__: This is probaby because your sources are not specified as sources in the project itself. Go to `File -> Project Properties`, click on `Modules`.
Now click on the folder that contains your sources (`src` in our case), and mark the folder as _Resources_.

__Q__: When I try to build and run the `Terminal` module, I get one of the following errors: _Cannot start compilation: the outpath path is not specified for module "Terminal". Specify the outpat path in Configure Project_ or _Error: Could not find or load main class Terminal_ 

__A__: This has something to do with the output path of the module. `File -> Project Structure` (or `CTRL + ALT + SHFT + S` for short), select the `Terminal` module. In the tab `Paths`, under `Compiler ouput` select `Inherit project compile output path`. On the left side, under Project Settings, click on `Project`. On the bottom, you see `Project compiler output`. This is the location where `.class` files of the module will be put. 
In your project, create an addition folder called `classes`, and put the __absolute__ location in this field (e.g. `C:\Users\%USERNAME%\Documents\ePurse\out\classes`, where `%USERNAME%` is your username).
Once done, click `Apply` on the bottom and you should be good to go.

# Installing Applets
To access the applets on the card, put the card in the cardreader and connect the cardreader with the computer.
The following commands can now be used (where `applet.cap` is the applet you want to install):

* __List applet__
  ```
  java -jar gp.jar -list
  ```
* __Install applet__
  ```
  java -jar gp.jar -install applet.cap
  ```
* __Delete applet__. An applet can be deleted by specifying the AID (Application Identifier) of the applet: 
  ```
  java -jar gp.jar --deletedeps --delete 3B2963616C6300
  ```
# Structure APDU messages

## SELECT command

Command APDU:

| CLA | INS | P1 | P2 | Lc | Data field | Le |
| ----|:---:| --:|--:| --:| --:| --:|
| 0x0 | 0xA4 | 0x04 | 0x0 | 0x08 | 0xF2, 0x34, 0x12, 0x34, 0x56, 0x10, 0x0, 0x1 | N/A |

Response APDU:

| Optional | Status word | Meaning |
| ----|:---:| --:|
| No data | 0xx9000 | Successful processing |
| | 0x6999 | Applet selection failed |

## VERIFY HI command

Command APDU:

| CLA | INS | P1 | P2 | Lc | Data field | Le |
| ----|:---:| --:|--:| --:| --:| --:|
| 0xB0 | 0x41 | 0x0 | 0x0 | 0x0 | 0x0 | N/A |

Response APDU:

| Optional | Status word | Meaning |
| ----|:---:| --:|
| No data | 0xx9000 | Successful processing |
| | 0x6300 | Verification failed |



## CREDIT command

Command APDU:

| CLA | INS | P1 | P2 | Lc | Data field | Le |
| ----|:---:| --:|--:| --:| --:| --:|
| 0xB0 | 0x30 | 0x0 | 0x0 | 1 | Credit amount | N/A |

Response APDU:

| Optional | Status word | Meaning |
| ----|:---:| --:|
| No data | 0xx9000 | Successful processing |
| | 0x6301 | PIN verification required |
| | 0x6A83 | Invalid credit amount |
| | 0x6A84 | Exceed the maximum amount |

## DEBIT command

Command APDU:

| CLA | INS | P1 | P2 | Lc | Data field | Le |
| ----|:---:| --:|--:| --:| --:| --:|
| 0xB0 | 0x40 | 0x0 | 0x0 | 1 | Debit amount | N/A |

Response APDU:

| Optional | Status word | Meaning |
| ----|:---:| --:|
| No data | 0xx9000 | Successful processing |
| | 0x6301 | PIN verification required |
| | 0x6A83 | Invalid debit amount |
| | 0x6A85 | Negative balance |

## VERIFY PIN command

Command APDU:

| CLA | INS | P1 | P2 | Lc | Data field | Le |
| ----|:---:| --:|--:| --:| --:| --:|
| 0xB0 | 0x20 | 0x0 | 0x0 | Length of the PIN data | PIN data | N/A |

Response APDU:

| Optional | Status word | Meaning |
| ----|:---:| --:|
| No data | 0xx9000 | Successful processing |
| | 0x6300 | Verification failed |
