# Overview

AaronLocker is designed to make the creation and maintenance of robust, strict, AppLocker-based whitelisting rules as easy and practical as possible. The entire solution involves a small number of PowerShell scripts. You can easily customize rules for your specific requirements with simple text-file edits. AaronLocker includes scripts that document AppLocker policies and capture event data into Excel workbooks that facilitate analysis and policy maintenance.

AaronLocker is designed to restrict program and script execution by non-administrative users. Note that AaronLocker does not try to stop administrative users from running anything they want – and AppLocker cannot meaningfully restrict administrative actions anyway. A determined user with administrative rights can easily bypass AppLocker rules.

AaronLocker’s strategy can be summed up as: if a non-admin could have put a program or script onto the computer – i.e., it is in a user-writable directory – don’t allow it to execute unless it has already been specifically allowed by an administrator. This will stop execution if a user is tricked into downloading malware, if an exploitable vulnerability in a program the user is running tries to put malware on the computer, or if a user intentionally tries to download and run unauthorized programs.

AaronLocker works on all supported versions of Windows that can provide AppLocker.

Part I of this document is a high-level description of whitelisting concepts, AppLocker, and the AaronLocker approach. Part II is the “operations guide” that digs into the details of implementing AaronLocker for your environment.

A personal note: the name “AaronLocker” was Chris (@appcompatguy) Jackson’s idea – not mine – and I resisted it for a long time. I finally gave in because I couldn’t come up with a better name.

# Demos

7 minute "Intro to 'AaronLocker'" (circa Feb. 2019):
https://youtu.be/nQyODwPR5qo

13 minute "AaronLocker Quick Start" - how to build, customize, and deploy robust and practical AppLocker rules quickly using AaronLocker (circa Feb. 2019):
https://youtu.be/E-IrqFtJOKU

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
