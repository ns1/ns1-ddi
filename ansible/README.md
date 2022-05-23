Role Name
=========

NS1-DDI

Role Variables
--------------
(Required)
* api_key: This is your API Key
* node_tags: This is a map of key/values to be used as tag_name:value

(Optional)
* register_node: This is a boolean set to false if you don't want to run the registerNode step (default: True)
* update_node: This is a boolean set to false if you don't want to run the updateNode step (default: True)
* bootstrap_node: This is a boolean set to false if you don't want to run the bootstrapNode step (default: True)
* deploy_node: This is a boolean set to false if you don't want to run the deployment step (default: True)

Dependencies
------------
This role has no dependencies

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: ns1.ns1-ddi, api_key: xxx, node_tags: {tag1: value1, tag2: value2 } }

License
-------

Apache 2

Author Information
------------------

* Jason Vervlied <jvervlied@ns1.com>
* Ed Ravin <eravin@ns1.com>
