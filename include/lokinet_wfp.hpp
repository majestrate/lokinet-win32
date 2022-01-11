#pramga once

#include <set>
#include <memory>
#include <windows.h>

namespace lokinet::win32
{
    /// private implementation of llarp::win32::Firewall
    class Firewall_impl;

    
    class Firewall
    {
        /// private implementation
        std::unqiue_ptr<Firewall_impl> _impl;
    public:

        struct Exclusion
        {
            /// network interface to allow this exclusion on
            LUID net_interface;
            /// ip dst address to allow traffic to
            uint32_t ip;
            /// udp dst port to allow traffic to
            uint16_t port;

            bool operator<(const Exclusion & ex) const
            {
                return net_interface < ex.net_interface
                    or ip < ex.ip
                    or port < ex.port;
            }
        };

        /// construct a new firewall with initial route exclusions
        /// @param lokinet_if the network interface owned by lokinet
        /// @param exclusions route rules to not shove over the lokinet interface
        /// will throw if windows decides it does not want to set up the firewall
        explicit Firewall(LUID lokinet_if, std::set<Exclusion> exclusions);


        /// tear down firewall, remove all rules, any failures will not throw so that the firewall sticks the rules
        ~Firewall();
        
        /// add a routing exclusion for ip:port for udp traffic to go on interface by LUID
        /// return an id of the exlcusion for removal
        /// throws if windows does not want to add the route exclusion
        int64_t
        AddExclusion(Exclusion exclude);

        /// remove routing exclusion by id
        /// if the exclusion by id does not exist it will silently continue
        void
        RemoveExclusion(int64_t id);

        /// remove routing exclusion given the entire rule
        void
        RemoveExclusion(Exclusion exclude);

        /// fetch a list of all the current routing exclusions
        std::set<Exclusion>
        ListExclusions() const;
        
        
    };

}
