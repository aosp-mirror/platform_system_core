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
      ]
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
          ]
        },
      ],
    }],
  ],
}
