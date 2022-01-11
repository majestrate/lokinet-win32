#include <lokinet_wfp.hpp>
#include <libwfp/filterengine.h>

namespace lokinet::win32
{
    class Firewall_impl;
    {
       
        std::unique_ptr<wfp::FilterEngine> _engine;
       wfp::SublayerBuilder _sublayer;
        GUID _sublayer_guid;
    public:
        Firewall_impl() :
            _engine{wfp::FilterEngine::StandardSession()},
            _sublayer{wfp::BuilderValidation::OnlyCritical}
            {
                _sublayer.name("lokinet packet filter").weight(MAXUINT16);
                wfp::ConditionBuilder conditions{FWPM_LAYER_ALE_AUTH_CONNECT_V4};
                conditons.add_condition();
            }
    };
}
