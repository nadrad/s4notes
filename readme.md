
# S4Notes

**Simple, [relatively] Secure, Self-hosted, Self-destructing Notes**

S4Notes is a web application for sending [sensitive] notes to others. Each note has a **maximum number of views**, an **expiry duration**, and, optionally, an **encryption passphrase**. It chooses a random-looking URL for each note unless you set a custom one. 

![A sample recording that shows how S4Notes works](./sample-recording.gif)

S4Notes is a single PHP file you can copy to any directory on your website, and it starts working without the need for configuration, database, etc. More about the installation is below.


## Use cases

I have two main use cases for S4Notes:

1. You need to send a password to someone. If you simply send it in an email or instant message, the sensitive content remains there, and someone may see it in the future. With S4Notes, you send a link instead, which expires afterward.
1. Once, I was in a conference and needed to add a streaming key to their computer. There was no email or instant messenger on that computer, and I didn't want to log in to any of my accounts on their computer. So, I added the note in a pastebin, used a URL shortener, and then typed that URL into their browser to get the key. With S4Notes, I can simply create a note containing the streaming key with a simple URL such as `example.com/notes/?s` and type that address in a browser on the target computer to get the key. 


## Why S4Notes?

There are many applications with more or less similar functionalities. Besides the urge to have something that works exactly the way I want it to, I had two reasons for writing this application:

1. I wanted it to be as easy as possible so that anyone could install it on their website and use it.
1. I also wanted something that helps with my second use case above, and the existing applications didn't.


## Security

Using something like this increases the security of the sensitive content you need to send to others, but nothing can make it completely secure; e.g., the recipient may just copy the content and store it in a plain text file on their desktop or write it on a sticky note and put on the corner of their monitor. There may not be much you can do about it, but you can at least remove a few other risks by using an application like this.


## Installation

For a simple installation, this is all you need to do:

1. Create a subdomain (e.g., `notes.example.com`) or a directory (e.g., `example.com/notes`) for the application.
1. Copy the `index.php` file from this repository to the target directory on your server.
1. Optionally, add the `favicon.ico` and `vault.png` files to the same directory.
1. Open the web page — it will ask you to set a master password, and then it will be ready for use.

Trouble-shooting:

1. If you see the application's source code when opening the page, it means that PHP files are not interpreted. Check to ensure PHP is installed on your server, and your web server knows what to do with PHP files.
1. Hmm... I can't think of anything else!

For more advanced users, instead of the method above, it's probably best to clone this repository on your server and set up a scheduled task to update it every week or so.


## To Do

* Check to make sure it works with older versions of PHP
* Change the master password from the web
* Support pretty URLs
* Send a note request
* Send emails when notes are viewed (optional)
* Add a config file
* Unban users from the web


## Feedback

Programming is not my profession. I do it as a hobby every once in a while. So, if you have any ideas for improving the code, I'd be glad to hear them. Ideas for new features and pull requests are welcome as well.

