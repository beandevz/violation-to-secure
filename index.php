<?php

    $action = $_GET['action'];
    $pageid = $_GET['pageid'];

    call_user_func($action,$pageid);

    ?>
