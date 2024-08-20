
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

### 3. **Write the Netpicker Rule**
   - **Basic Structure**: Use the Netpicker rule template:
     ```python
     @low(
        name='rule_name',
        platform=['platform_name'],
     )
     def rule_name(configuration):
         assert 'keyword' in configuration
     ```
   - **Customize the Rule**:
     - Replace `'rule_name'` with your actual rule name.
     - Specify the correct platform(s).
     - Implement the logic inside the function, using assertions to determine if the device complies with the rule.
