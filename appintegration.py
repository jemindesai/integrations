import yaml

class AppIntegration:
    """
    All app integrations for Orchestrator inherit from AppIntegration.
    """
    def __init__(self):
        self.secrets = self.read_secrets('secrets.yml')

    def read_secrets(self, filename):
        """
        Parses the YAML file with name FILENAME into
        a dictionary.
        """
        with open(filename, 'r') as stream:
            try:
                return yaml.load(stream)
            except yaml.YAMLError as error:
                print("Error: Could not parse %s" % filename)
                print(error)
