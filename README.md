# radius_server
A very simple radius server capable of implementing service logic. It can be very useful for fast deployment of testing scenarios.

I know there are some very good free radius servers out there but most of them will require installing software packages and going through complex configuration files that most of the times are not needed to implement very simple logic. An example could be authenticating users through a username/password list.

To setup this Radius Server you just need to download and these files and run the Python 3 script that takes a single configuration file as an argument. 

radius_server.py -c radius_user_auth.conf

The radius dictionary file included (radius.dict) must be in the same folder as the script but you do not need to do anything with it (...only if you need to define new radius AVPs).

I tried to make your life easy by providing a few example configuration files that you can also check out.

The configuration file starts by declaring some basic stuff I think it is self explanatory:

listen_ip = 0.0.0.0
listen_auth_port = 1812
listen_acct_port = 1813

#workers will be forked only in Linux based systems
workers = 4

dictionary_filename = radius.dict
log_filename = radius.log
 
This Radius Server will listen on the default radius protocol ports for authentication (UDP 1812) and for accounting (UDP 1813). It will also accept incoming packets on every IP interface. In Linux systems 8 processes will be created 4 for authentication and another 4 for accounting. You might want to specify a different log filename.

Then comes the server's logic configuration. The two most important sections are the "rules" and the "actions". It works like this: 

* To each rule is given a number that defines the order how rules are evaluated. The server follows an ascending order.

* Server actions are also numbered so they can be referenced by the rules.

* Rules are evaluated against some criteria (e.g. "user_authentication", "attribute_matches", "user_profile_matches",...). 

* If the evaluated criteria returns "TRUE" the server can either take an action or evaluate some other rule.

* If the evaluated criteria returns "FALSE" the server evaluates the rule that follows obeying the defined order.

* It is possible to create a chain of rules to match a set of criteria and only take some action if all return "TRUE".

* After executing an action the server will check if there is a defined next action to execute. If not a reply packet or a proxied packet will be sent.   

Radius users are also defined in the same configuration file:

users = {
            "jorge@test.pt":{"user_profile":"Internet", "password_format":"md5", "password":"3f9ca55a7dd359fa11a7d6dee0d45774"},
            "john@test.pt":{"user_profile":"Internet", "password_format":"clear", "password":"john_password123"},
            "eva@test.pt":{"user_profile":"Internet", "password_format":"clear", "password":"eva_password123"},
            "albert@test.pt":{"user_profile":"Internet", "password_format":"clear", "password":"albert_password123"}
        }

Passwords can be stored as clear text or as a MD5 hash. The user profile field is useful to differentiate users. But more on profiles later...

Let's take a look at a very simple example:

rules = {   
            "1":{"criteria":"is_authentication", "next_rule":"100"},
            "5":{"criteria":"is_accounting", "action":"500"},
            "100":{"criteria":"user_authentication", "action":"100"},
            "200":{"criteria":"none", "action":"200"}
        }
 
actions = {
            "100":{"action":"accept", "next_action":"101"},
            "101":{"action":"add_attribute","attribute_name":"Chargeable-User-Identity","attribute_value":"ABC123"},
            "200":{"action":"reject", "next_action":"201"},
            "201":{"action":"add_attribute","attribute_name":"Reply-Message","attribute_value":"User not allowed!"},
            "500":{"action":"accept"}
          } 

All valid users will get back an Access-Accept message with the Chargeable-User-Identity AVP set to "ABC123". Non authenticated users will get an Access-Reject with the Reply-Message AVP set to "User not allowed!". Accounting requests just get an Ack with no AVPs as a reply.
 
If you remove actions 101 and 201 from the configuration you will only get either an Access-Accept if the username and password are correct or an Access-Reject if not but in both cases without any included AVPs.

It is also very straightforward to add more reply AVPs. For example to add a Class AVP to the Access-Accept just add an action 102 like so:

 actions = {
            "100":{"action":"accept", "next_action":"101"},
            "101":{"action":"add_attribute","attribute_name":"Chargeable-User-Identity","attribute_value":"ABC123", "next_action":"102"},
            "102":{"action":"add_attribute","attribute_name":"Class","attribute_value":"bla bla bla "},
            "200":{"action":"reject", "next_action":"201"},
            "201":{"action":"add_attribute","attribute_name":"Reply-Message","attribute_value":"User not allowed!"},
            "500":{"action":"accept"}
          } 
Just make sure you pick an AVP included in the radius dictionary file that is loaded when the program starts.

Before trying this out be sure to include your radius client on the authorized clients list. Otherwise all messages will be ignored by the server.

clients = {
            "10.0.2.15/32":{"secret":"secret"}   
          }  

You can either include specific host using a /32 netmask or a whole network (e.g. 10.0.2.0/24). The radius secret (that is set to "secret" in this example) can be whatever you like.

To speed things up a little I included a set of configuration files you can adjust to fit your needs. If even so you get stuck send me an email and I will help you out. 

And if you want to test all these use cases you might also want to try the testing script that will generate radius request packets. Make sure you set the destination IP and authentication port accordingly. You might want to use Wireshark to capture the radius packets and look at the results.
