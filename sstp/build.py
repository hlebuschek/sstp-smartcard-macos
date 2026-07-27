"""Identity of this copy of the package.

install copies the package out of the app bundle and launchd keeps running that
copy, so replacing the app leaves the daemon on the previous code with nothing
to show for it. make-app.sh stamps this file inside the bundle; the interface
compares the stamp it was built with against the one the daemon reports.
"""

BUILD = "dev"
