"""
Client Metadata Files
=====================

Parsers for files that are generated by the insights-client.

AnsibleHost - File ``ansible_host``
-----------------------------------

BlacklistedSpecs - File ``blacklisted_specs``
---------------------------------------------

BranchInfo - File ``branch_info``
---------------------------------

DisplayName - File ``display_name``
-----------------------------------

MachineID - File ``machine_id``
-------------------------------

Tags - file ``tags.json``
-------------------------

VersionInfo - file ``version_info``
-----------------------------------
"""
from insights.core import Parser, JSONParser
from insights.core.exceptions import SkipComponent
from insights.core.plugins import parser
from insights.parsers.hostname import HostnameBase
from insights.specs import Specs


@parser(Specs.ansible_host)
class AnsibleHost(HostnameBase):
    """
    Class for parsing the content of ``ansible_host``.

    Typical content::

        host1

    Attributes:
        hostname (str): Ansible Hostname.
        raw (str): RAW content of this file.

    Examples:
        >>> type(ansible_host)
        <class 'insights.parsers.client_metadata.AnsibleHost'>
        >>> ansible_host.hostname == "host1"
        True
        >>> ansible_host.raw == "host1"
        True
    """
    pass


@parser(Specs.blacklisted_specs)
class BlacklistedSpecs(JSONParser):
    """
    Class for parsing the content of ``blacklisted_specs`` or
    ``blacklisted_specs.txt``

    Typical content::

        {"specs": ["dmesg", "fstab"]}

    Attributes:
        specs (list): List of blacklisted specs.

    Examples:
        >>> type(specs)
        <class 'insights.parsers.client_metadata.BlacklistedSpecs'>
        >>> result = ['dmesg', 'fstab']
        >>> specs.specs == result
        True
    """
    @property
    def specs(self):
        return self.data['specs']


@parser(Specs.branch_info)
class BranchInfo(JSONParser):
    """
    Class for parsing the content of ``branch_info`` as a dictionary.

    Typical content::

        {"remote_branch": -1, "remote_leaf": -1}

    Examples:
        >>> type(branch_info)
        <class 'insights.parsers.client_metadata.BranchInfo'>
        >>> branch_info['remote_branch'] == -1
        True
    """
    pass


@parser(Specs.display_name)
class DisplayName(HostnameBase):
    """
    Class for parsing the content of ``display_name``.

    Typical content::

        host1

    Attributes:
        hostname (str): Display Hostname.
        raw (str): RAW content of this file.

    Examples:
        >>> type(display_name)
        <class 'insights.parsers.client_metadata.DisplayName'>
        >>> display_name.hostname == "host1"
        True
        >>> display_name.raw == "host1"
        True
    """
    pass


@parser(Specs.machine_id)
class MachineID(Parser):
    """
    Class for parsing the content of ``display_name``.

    Typical content::

        176843d1-90fa-499b-9f94-111111111111

    Attributes:
        id (str): Machine ID

    Examples:
        >>> type(machine_id)
        <class 'insights.parsers.client_metadata.MachineID'>
        >>> machine_id.id== "176843d1-90fa-499b-9f94-111111111111"
        True

    Raises:
        SkipComponent: Nothing collected
    """
    def parse_content(self, content):
        if not content or len(content) > 1:
            raise SkipComponent()
        self.id = content[0].strip()


@parser(Specs.tags)
class Tags(JSONParser):
    """
    Class for parsing the content of ``tags.json``.

    Typical content::

        [{"key": "group", "value": "_group-name-value_", "namespace": "insights-client"}]

    Attributes:
        data (list): List of parsed dictionaries.

    Examples:
        >>> type(tags)
        <class 'insights.parsers.client_metadata.Tags'>
        >>> tags.data[0]['key'] == "group"
        True
        >>> tags.data[0]['value'] == "_group-name-value_"
        True
        >>> tags.data[0]['namespace'] == "insights-client"
        True
    """
    pass


@parser(Specs.version_info)
class VersionInfo(JSONParser):
    """
    Class for parsing the content of ``version_info``.

    Typical content of this file is::

        {"core_version": "3.0.203-1", "client_version": "3.1.1"}

    .. note::

        The :attr:`client_version` provided by this Parser is a short version
        only, to get the full version of the ``insights-client`` package,
        please use the :class:`insights.parsers.installed_rpms.InstalledRpms`
        Parser instead.

    Examples:
        >>> type(ver)
        <class 'insights.parsers.client_metadata.VersionInfo'>
        >>> ver.core_version == '3.0.203-1'
        True
        >>> ver.client_version == '3.1.1'
        True
    """
    @property
    def core_version(self):
        """
        Returns:
            (str): The version of the insights core.
        """
        return self['core_version']

    @property
    def client_version(self):
        """
        Returns:
            (str): The version of the insights client.

        .. note::

            This attribute returns a short version of the insights client only,
            to get the full version of the ``insights-client`` package, please
            use the :class:`insights.parsers.installed_rpms.InstalledRpms` Parser
            instead.
        """
        return self['client_version']
