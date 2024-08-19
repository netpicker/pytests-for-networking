
<img src="https://netpicker.io/wp-content/uploads/2024/01/netpicker-logo-276x300.png" width="160">




Compliance Examples
=======

A set of common Netpicker compliance use-cases.

<br />

## Table of contents

#### Format of the rules

#### Simple Examples

#### Multiple lines

#### Multiple commands

#### Using Textfsm

## Format of the rules
### 2. **Understand the Netpicker Rule Structure**
   - **Severity Levels**: Decide whether your rule should be low, medium, or high severity, depending on its importance.
   - **Rule Naming**: Name your rule starting with `rule_`, followed by a descriptive name that reflects the test's purpose.
   - **Platform Specification**: Identify the platforms (e.g., `cisco_ios`, `juniper`) the rule applies to.

<<<<<<< HEAD
### 3. **Write the Netpicker Rule**
   - **Basic Structure**: Use the Netpicker rule template:
     ```python
     @low(
        name='rule_name',
        platform=['platform_name'],
        commands={'command_name': 'command_to_execute'},
     )
     def rule_name(configuration, commands, device, devices):
         assert 'keyword' in configuration
     ```
   - **Customize the Rule**:
     - Replace `'rule_name'` with your actual rule name.
     - Specify the correct platform(s).
     - Define the commands needed for the test.
     - Implement the logic inside the function, using assertions to determine if the device complies with the rule.

   **Example**:
   ```python
   @medium(
      name='rule_no_default_route',
      platform=['cisco_ios'],
      commands={'show_route': 'show ip route'},
   )
   def rule_no_default_route(configuration, commands, device, devices):
       assert '0.0.0.0/0' not in commands.show_route
   ```
   - **Testing Logic**: The example above checks if a default route (0.0.0.0/0) exists in the device's route table.
=======
Severity Levels: Decide whether your rule should be low, medium, or high severity, depending on its importance.
Rule Naming: Name your rule starting with rule_, followed by a descriptive name that reflects the test's purpose.
Platform Specification: Identify the platforms (e.g., cisco_ios, juniper_junos) the rule applies to.

>>>>>>> 8f545d58de8f7630595937c74364be580766fba3
