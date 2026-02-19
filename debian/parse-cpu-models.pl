#!/usr/bin/perl

use v5.36;

use JSON qw(to_json);

# NOTE: Only the alias names were exposed in qemu-server before the info was created during build
# of pve-qemu. Continue to do so.

my @skip_models = (
    'base',
    'host', # added in qemu-server depending on arch

    # x86_64
    'n270',
    'Denverton',
    'Snowridge',
    # some more are skipped based on vendor

    # aarch64
    'arm1026',
    'arm1136',
    'arm1136-r2',
    'arm1176',
    'arm11mpcore',
    'arm926',
    'arm946',
    'cortex-a7',
    'cortex-a8',
    'cortex-a9',
    'cortex-a15',
    'cortex-m0',
    'cortex-m3',
    'cortex-m33',
    'cortex-m4',
    'cortex-m55',
    'cortex-m7',
    'cortex-r5',
    'cortex-r52',
    'cortex-r5f',
    'sa1100',
    'sa1110',
    'ti925t',
    # some more are skipped based on being deprecated
);
my $skip_models_re = qr/(@{[join('|', @skip_models)]})/;

my $cpu_models = {};
my $aliases = {};

while (my $line = <STDIN>) {
    last if $line =~ /^\s*Recognized CPUID flags:/;
    next if $line =~ /^\s*Available CPUs:/;
    next if $line =~ /^$/;

    $line =~ s/^\s+//;
    $line =~ s/\s+$//;

    my ($model, $info) = ($line =~ m/^(\S+)\s*(.*)$/) or die "unexpected line '$line'\n";

    if ($model eq 'athlon-v1') {
        # has unusual info: QEMU Virtual CPU version 2.5+
        $cpu_models->{$model} = 'AuthenticAMD';
        next;
    } elsif ($model =~ m/^((kvm|qemu)(32|64)-v1|max)$/) {
        $cpu_models->{$model} = 'default';
        next;
    } elsif ($model =~ m/^$skip_models_re(-v\d)?$/) {
        next; # skip
    }

    if (!$info) {
        if ($model =~ m/^(486|pentium(2|3)?)-v1$/) {
            $cpu_models->{$model} = 'GenuineIntel';
            next;
        } elsif ($model =~ m/^(a64fx|cortex-|neoverse-).*$/) {
            $cpu_models->{$model} = 'ARM';
            next;
        }
        die "unable to deal with line '$line' - implement me"
    } elsif ($info =~ m/^\(deprecated\)$/) {
        next;
    } elsif ($info =~ m/^\(alias configured by machine type\)/) {
        # For now, such an alias always corresponds to the -v1 for q35 and i440fx (not for microvm)
        $aliases->{$model} = "${model}-v1";
        next;
    } elsif ($info =~ m/^\(alias of (\S+)\)/) {
        # alias will be resolved later
        $aliases->{$model} = $1;
        next;
    } elsif ($info =~ m/^(Hygon|YongFeng|Zhaoxin)/) {
        next; # skip
    } elsif ($info =~ m/^AMD/) {
        $cpu_models->{$model} = 'AuthenticAMD';
        next;
    } elsif ($info =~ m/^(Intel|Genuine Intel|Westmere)/) {
        $cpu_models->{$model} = 'GenuineIntel';
        next;
    }

    die "unable to deal with line '$line' - implement me";
}

# Backwards compat - resolve the alias and only expose the alias.
for my $alias (keys $aliases->%*) {
    my $target = $aliases->{$alias};
    # an alias might refer to a model that was skipped
    next if !exists($cpu_models->{$target});
    $cpu_models->{$alias} = $cpu_models->{$target};
    delete $cpu_models->{$target};
}

# Backwards compat - there never was such a client CPU, but it was exposed in the past - mapped to
# the corresponding server CPU model in qemu-server.
if ($cpu_models->{'Icelake-Server'}) {
    $cpu_models->{'Icelake-Client'} = 'GenuineIntel';
    $cpu_models->{'Icelake-Client-noTSX'} = 'GenuineIntel';
}

print to_json($cpu_models, { utf8 => 1, canonical => 1, pretty => 1 })
    or die "failed to encode detected CPU models as JSON - $!\n";
