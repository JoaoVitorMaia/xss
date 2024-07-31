### Purpose

The tool aims to identify html injection possibilities in GET parameters, letting the hard part of constructing the xss payload for the user, preventing false negatives by firewall blocking

### Install

<code>go install github.com/joaovitormaia/xss@latest</code>

### Usage
<code>cat urls.txt | xss -o output.txt</code>

<code>xss -i urls.txt</code>

### Help
<code>xss -h</code>
