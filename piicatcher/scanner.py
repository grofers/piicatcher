"""Different types of scanners for PII data"""
import logging
import re
from abc import ABC, abstractmethod

import spacy
from commonregex import CommonRegex

from piicatcher.piitypes import PiiTypes

# pylint: disable=too-few-public-methods
class Scanner(ABC):
    """Scanner abstract class that defines required methods"""

    @abstractmethod
    def scan(self, text):
        """Scan the text and return an array of PiiTypes that are found"""


class RegexScanner(Scanner):
    """A scanner that uses common regular expressions to find PII"""

    def scan(self, text):
        """Scan the text and return an array of PiiTypes that are found"""
        regex_result = CommonRegex(text)

        types = []
        if regex_result.phones:  # pylint: disable=no-member
            types.append(PiiTypes.PHONE)
        if regex_result.emails:  # pylint: disable=no-member
            types.append(PiiTypes.EMAIL)
        if regex_result.credit_cards:  # pylint: disable=no-member
            types.append(PiiTypes.CREDIT_CARD)
        if regex_result.street_addresses:  # pylint: disable=no-member
            types.append(PiiTypes.ADDRESS)

        return types


class NERScanner(Scanner):
    """A scanner that uses Spacy NER for entity recognition"""

    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")

    def scan(self, text):
        """Scan the text and return an array of PiiTypes that are found"""
        logging.debug("Processing '%s'", text)
        doc = self.nlp(text)
        types = set()
        for ent in doc.ents:
            logging.debug("Found %s", ent.label_)
            if ent.label_ == "PERSON":
                types.add(PiiTypes.PERSON)

            if ent.label_ == "GPE":
                types.add(PiiTypes.LOCATION)

            if ent.label_ == "DATE":
                types.add(PiiTypes.BIRTH_DATE)

        logging.debug("PiiTypes are %s", ",".join(str(x) for x in list(types)))
        return list(types)


class ColumnNameScanner(Scanner):
    def __init__(self, exclude_regex=()):
        self._exclude_regex = None
        if len(exclude_regex) > 0:
            self._exclude_regex = re.compile(exclude_regex[0], re.IGNORECASE)   # [0] cause the option comes as tuple
    regex = {
        PiiTypes.PERSON: re.compile(
            "^.*(firstname|fname|lastname|lname|"
            "fullname|maidenname|_name|"
            "nickname|name_suffix|name).*$",
            re.IGNORECASE,
        ),
        PiiTypes.EMAIL: re.compile("^.*(email|e-mail|mail).*$", re.IGNORECASE),
        PiiTypes.BIRTH_DATE: re.compile(
            "^.*(date_of_birth|dateofbirth|dob|"
            "birthday|date_of_death|dateofdeath).*$",
            re.IGNORECASE,
        ),
        PiiTypes.GENDER: re.compile("^.*(gender).*$", re.IGNORECASE),
        PiiTypes.NATIONALITY: re.compile("^.*(nationality).*$", re.IGNORECASE),
        PiiTypes.ADDRESS: re.compile(
            "^.*(addr|state|county|country|" "zipcode|postal|zone|borough|line1|line_|line2|pincode|landmark|contact).*$",    # replacing address with addr
            re.IGNORECASE,
        ),
        PiiTypes.USER_NAME: re.compile("^.*user(id|name|).*$", re.IGNORECASE),
        PiiTypes.PASSWORD: re.compile("^.*(pass|access_token).*$", re.IGNORECASE),
        PiiTypes.SSN: re.compile("^.*(ssn|social|aadhar|adhaar|aadhaar|pan).*$", re.IGNORECASE),
        PiiTypes.PHONE: re.compile("^.*(phone|mobile|mob_).*$", re.IGNORECASE),
        PiiTypes.LOCATION: re.compile("^.*(location|lat|lon).*$", re.IGNORECASE),
    }

    def scan(self, text):
        types = set()
        if self._exclude_regex is not None:
            for pii_type in self.regex:
                if self.regex[pii_type].match(text) is not None and self._exclude_regex.match(text) is None:    # excluded_regex shouldn't match
                    types.add(pii_type)
        else:
            for pii_type in self.regex:
                if self.regex[pii_type].match(text) is not None:
                    types.add(pii_type)

        logging.debug("PiiTypes are %s", ",".join(str(x) for x in list(types)))
        return list(types)
