
# CV EOS Conversion tool

Even though this script is best effort supported, please send any issues you find, suggestions for improvements etc to: [po@arista.com](mailto:po@arista.com).  Please use the subject: **CV EOS Conversion tool**

I also want to give credit to Steve Ulrich, Thomas Smith and Jonathan Smith for reviewing and contributing to the code and regexes. They have been a great help debugging the tool!

This tool is meant to be used from a Linux Python script host (Python 2.6, 2.7 and 3.x) and connect to CVPs REST API. Current tested CVP version is 2019.1.x. There is work put into making the tool CVP 2020.1.x compatible. The script itself uses the provided CloudVisiob Python based API.  All files needed to use the Python based API is provided in this repo.  Make sure to clone all files to your directory.

There is a `TEST-CONFIGLET.TXT` which can be pasted into a static configlet.  The file have all old CLI configs that will be changed. The thought here is to have something to test on.

The script will connect to CVP and open all static configlets. It will look for all CLI changes and update the configlets. This means a lot of tasks will be created and when running them basically just the running config changes withoutany impact on data plane or control plane. All that really happens is that config is saved in the new CLI format in running-config and startup-config.

Known caveats right now:

* The CLI changes apply to EOS with versions 4.21.x and above. So if you are running vRouters that are at max EOS version 4.20.x, the changes will be applied and fail. This doesnt impact anything, but it forces you to edit the vRouters configlets and change to old CLI commands again.

* `system control-plane` can be translated by mistake to `system system control-plane`

* The tool is meant to be used on static configlets. Any generated configlets by configlet builders should be updated through editing the configlet builder to use new CLI syntax.

* In interface config mode:
	`ip igmp query-max-response-time` is meant to change to `igmp query-max-response-time` Right now it is not changed, because it overlaps with a command in `router igmp`.

* In router igmp config mode:
	`ip igmp query-max-response-time` is meant to change to `query-max-response-time` Right now it is not changed, because it overlaps with a command in interface config mode.

* In router isis config mode:
	`passive-interface` is meant to change to `passive`	Right now it is not changed since it conflicts with several other config modes using `passive-interface`.

* In router rip config mode:
	`default-metric` is meant to change to `metric default`	Right now it is not changed since it conflicts with several other config modes using `default-metric`.

Below is an explanation of all command line options to `CVEOSConversion.py`:

```
 -c, --cvphostname  Mandatory, provides CVP host name FQDN or IP for
                    CVP REST API connection.

 -u, --cvpusername	Mandatory, provides CVP username for CVP REST API connection.

 -p, --cvppassword	Optional, provides CVP password for CVP REST API connection. If not used, the script will prompt for 
 			prompt for the password.
 
 -d, --debug        Optional, default is 'no'. If debug is yes, nothing will
                    actually be sent to CVP and proposed configs are
                    written to terminal.

-t, --trace         Optional, default is 'no'. If trace is yes, alongside
                    actual changes to CVP configlets, there will be
                    trace messages to terminal.  
```

Thx, Patrik Olsson, Systems Engineer Arista Networks

