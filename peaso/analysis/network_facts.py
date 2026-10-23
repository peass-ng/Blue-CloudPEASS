"""Read-only projections shared by the network readers of one native resource.

Graph construction supplies its already recorded observations. The projected
native tree is lazy and released with this resource's reference readers, rather
than retaining a second projected inventory for the whole scan.
"""


class NetworkFacts:
    __slots__ = ('data', '_observations', '_projected', '_projected_ready')

    def __init__(self, data, *, observations=None):
        self.data = data
        self._observations = observations
        self._projected = None
        self._projected_ready = False

    def observations(self):
        if self._observations is None:
            from .network_observations import network_observations
            self._observations = network_observations(self.data)
        return self._observations

    def projected(self):
        if not self._projected_ready:
            from .network_services import project_network_data
            projected = project_network_data(self.data)
            self._projected = projected
            self._projected_ready = True
        return self._projected
