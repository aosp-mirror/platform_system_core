{
  'variables': {
    'libbase_ver': 271506,
  },
  'target_defaults': {
    'variables': {
      'deps': [
        'dbus-1',
        'dbus-glib-1',
        'glib-2.0',
        'gobject-2.0',
        'gthread-2.0',
        'libchrome-<(libbase_ver)',
        'libchromeos-<(libbase_ver)',
        'libcurl',
      ]
    },
    'cflags_cc': [
      '-fno-exceptions',
    ],
  },
  'targets': [
    {
      'target_name': 'libmetrics_daemon',
      'type': 'static_library',
      'dependencies': [
        '../metrics/libmetrics-<(libbase_ver).gyp:libmetrics-<(libbase_ver)',
        'libupload_service',
        'metrics_proto',
      ],
      'link_settings': {
        'libraries': [
          '-lrootdev',
          '-lgflags',
        ],
      },
      'sources': [
        'persistent_integer.cc',
        'metrics_daemon.cc',
        'metrics_daemon_main.cc',
      ],
      'include_dirs': ['.'],
    },
    {
      'target_name': 'metrics_client',
      'type': 'executable',
      'dependencies': [
        '../metrics/libmetrics-<(libbase_ver).gyp:libmetrics-<(libbase_ver)',
      ],
      'sources': [
        'metrics_client.cc',
      ]
    },
    {
      'target_name': 'libupload_service',
      'type': 'static_library',
      'dependencies': [
        'metrics_proto',
        '../metrics/libmetrics-<(libbase_ver).gyp:libmetrics-<(libbase_ver)',
      ],
      'link_settings': {
        'libraries': [
          '-lgflags',
          '-lvboot_host',
        ],
      },
      'variables': {
        'exported_deps': [
          'protobuf-lite',
        ],
        'deps': [
          '<@(exported_deps)',
        ],
      },
      'all_dependent_settings': {
        'variables': {
          'deps+': [
            '<@(exported_deps)',
          ],
        },
      },
      'sources': [
        'uploader/upload_service.cc',
        'uploader/metrics_log.cc',
        'uploader/system_profile_cache.cc',
        'uploader/curl_sender.cc',
        'components/metrics/metrics_log_base.cc',
        'components/metrics/metrics_log_manager.cc',
        'components/metrics/metrics_hashes.cc',
      ],
      'include_dirs': ['.']
    },
    {
      'target_name': 'metrics_proto',
      'type': 'static_library',
      'variables': {
        'proto_in_dir': 'components/metrics/proto/',
        'proto_out_dir': 'include/components/metrics/proto',
      },
      'sources': [
        '<(proto_in_dir)/chrome_user_metrics_extension.proto',
        '<(proto_in_dir)/histogram_event.proto',
        '<(proto_in_dir)/omnibox_event.proto',
        '<(proto_in_dir)/perf_data.proto',
        '<(proto_in_dir)/profiler_event.proto',
        '<(proto_in_dir)/sampled_profile.proto',
        '<(proto_in_dir)/system_profile.proto',
        '<(proto_in_dir)/user_action_event.proto',
      ],
      'includes': [
        '../../platform2/common-mk/protoc.gypi'
      ],
    },
  ],
  'conditions': [
    ['USE_passive_metrics == 1', {
      'targets': [
        {
          'target_name': 'metrics_daemon',
          'type': 'executable',
          'dependencies': ['libmetrics_daemon'],
        },
      ],
    }],
    ['USE_test == 1', {
      'targets': [
        {
          'target_name': 'persistent_integer_test',
          'type': 'executable',
          'includes': ['../../platform2/common-mk/common_test.gypi'],
          'sources': [
            'persistent_integer.cc',
            'persistent_integer_test.cc',
          ]
        },
        {
          'target_name': 'metrics_library_test',
          'type': 'executable',
          'dependencies': [
            '../metrics/libmetrics-<(libbase_ver).gyp:libmetrics-<(libbase_ver)',
          ],
          'includes': ['../../platform2/common-mk/common_test.gypi'],
          'sources': [
            'metrics_library_test.cc',
          ],
          'link_settings': {
            'libraries': [
              '-lpolicy-<(libbase_ver)',
            ]
          }
        },
        {
          'target_name': 'timer_test',
          'type': 'executable',
          'includes': ['../../platform2/common-mk/common_test.gypi'],
          'sources': [
            'timer.cc',
            'timer_test.cc',
          ]
        },
        {
          'target_name': 'upload_service_test',
          'type': 'executable',
          'sources': [
            'persistent_integer.cc',
            'uploader/mock/sender_mock.cc',
            'uploader/upload_service_test.cc',
          ],
          'dependencies': [
            'libupload_service',
          ],
          'includes':[
            '../../platform2/common-mk/common_test.gypi',
          ],
          'include_dirs': ['.']
        },
      ],
    }],
    ['USE_passive_metrics == 1 and USE_test == 1', {
      'targets': [
        {
          'target_name': 'metrics_daemon_test',
          'type': 'executable',
          'dependencies': [
            'libmetrics_daemon',
          ],
          'includes': ['../../platform2/common-mk/common_test.gypi'],
          'sources': [
            'metrics_daemon_test.cc',
          ],
          'include_dirs': ['.'],
        },
      ],
    }],
  ]
}
